use std::num::NonZeroU64;

use super::*;
use crate::proto::http1::fixture;

const ASKED: Asked = Asked {
    head: false,
    ignore_length: false,
    max_filesize: None,
    decode_codings: false,
    raw_codings: false,
};

const PLAIN: Exchange = Exchange {
    sent: HttpVersion::Http11,
    reused: false,
    allow_09: false,
    asked: ASKED,
};

/// What a head came to: each line given out with its kind, the body
/// after it, and the error that ended it, if one did.
#[derive(Debug, PartialEq, Eq)]
struct Outcome {
    lines: Vec<(LineKind, Vec<u8>)>,
    /// What C said of the lines, in order.
    notes: Vec<Note>,
    body: Vec<u8>,
    error: Option<HeadError>,
    framing: Option<Framing>,
    close: bool,
    /// The body's size as the head gives it.
    size: Option<u64>,
}

/// Feed `chunks` in turn, each as far as the parser takes it.
fn parse(chunks: &[&[u8]], exchange: Exchange, transfer_bytes: &mut u64) -> Outcome {
    let mut p = HeadParser::new(exchange);
    let mut out = Outcome {
        lines: Vec::new(),
        notes: Vec::new(),
        body: Vec::new(),
        error: None,
        framing: None,
        close: false,
        size: None,
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
                    out.notes.extend(line.note);
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
    out.framing = p.framing();
    out.close = p.meta().close();
    out.size = p.meta().size();
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

/// Only interim heads, and no body, is nothing that counts: as the C
/// tool showed for a lone "100 Continue". A final head's status line
/// alone is something.
#[test]
fn interim_heads_alone_are_nothing() {
    let fed = |reply: &[u8]| {
        let mut p = HeadParser::new(PLAIN);
        let mut transfer = 0;
        let mut input = reply;
        while !input.is_empty() {
            let (used, _) = p.feed(input, &mut transfer).unwrap();
            input = &input[used..];
        }
        p
    };
    let p = fed(b"HTTP/1.1 100 Continue\r\n\r\n");
    assert!(p.got_nothing(0));
    assert!(!p.got_nothing(1), "a body byte counts");
    let p = fed(b"HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200 OK\r\n");
    assert!(!p.got_nothing(0));
    let p = fed(b"HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200 OK\r\n\r\n");
    assert!(!p.got_nothing(0), "a final head's bytes count");
    assert!(fed(b"").got_nothing(0));
}

fn asked(f: impl FnOnce(&mut Asked)) -> Exchange {
    let mut exchange = PLAIN;
    f(&mut exchange.asked);
    exchange
}

/// Transfer-Encoding overrides Content-Length, and a coding other than
/// chunked is ended by the close; with `--raw` an unknown one is passed
/// on (tests 365, 2918).
#[test]
fn a_transfer_coding_overrides_the_length() {
    let got = outcome(&fixture::reply(365), PLAIN);
    assert_eq!(
        (got.error, got.framing, got.close),
        (None, Some(Framing::Chunked), false)
    );
    let raw = asked(|a| a.raw_codings = true);
    let got = outcome(&fixture::reply(2918), raw);
    assert_eq!(
        (got.error, got.framing, got.close),
        (None, Some(Framing::UntilClose), true)
    );
    // The length is void only from the coding on.
    let got = outcome(
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: x\r\nContent-Length: junk\r\n\r\n",
        raw,
    );
    assert_eq!(got.framing, Some(Framing::UntilClose));
    let got = outcome(
        b"HTTP/1.1 200 OK\r\nContent-Length: junk\r\nTransfer-Encoding: x\r\n\r\n",
        raw,
    );
    assert_eq!(got.error, Some(HeadError::Framing(FramingError::BadLength)));
}

/// Codings not asked for are refused, chunked must come last, and five is
/// the most (tests 1722, 1723, 2119).
#[test]
fn transfer_codings_are_refused_as_c_refuses_them() {
    let refused = |reply: &[u8], exchange| match outcome(reply, exchange).error {
        Some(HeadError::Framing(e)) => (e.to_string(), HeadError::Framing(e).kind()),
        other => panic!("{other:?}"),
    };
    let bad = ErrorKind::BadContentEncoding;
    assert_eq!(
        refused(&fixture::reply(1722), PLAIN),
        (
            "A Transfer-Encoding (another) was listed after chunked".into(),
            bad
        )
    );
    assert_eq!(
        refused(&fixture::reply(1723), PLAIN),
        (
            "A Transfer-Encoding (another) was listed after chunked".into(),
            bad
        )
    );
    assert_eq!(
        refused(&fixture::reply(2119), PLAIN),
        (
            "Unsolicited Transfer-Encoding (identityx) found".into(),
            bad
        )
    );
    let head = |te: &str| format!("HTTP/1.1 200 OK\r\nTransfer-Encoding: {te}\r\n\r\n");
    assert_eq!(
        outcome(head(" , identity,,chunked ").as_bytes(), PLAIN).framing,
        Some(Framing::Chunked),
        "identity is nothing"
    );
    assert_eq!(
        refused(head("x y, chunked").as_bytes(), PLAIN).0,
        "Unsolicited Transfer-Encoding (x y) found"
    );
    let decoding = asked(|a| a.decode_codings = true);
    assert_eq!(
        refused(head("chunked, gzip").as_bytes(), decoding).0,
        "Reject response due to 'chunked' not being the last Transfer-Encoding"
    );
    assert_eq!(
        outcome(head("a, b, c, d, chunked").as_bytes(), decoding).framing,
        Some(Framing::Chunked)
    );
    assert_eq!(
        refused(head("a, b, c, d, e, chunked").as_bytes(), decoding).0,
        "Reject response exceeding limit of 5 transfer encodings"
    );
    assert_eq!(
        outcome(head("chunked, chunked").as_bytes(), decoding).framing,
        Some(Framing::Chunked),
        "a second chunked is ignored"
    );
}

/// No body is read for a HEAD, a 204 or a 304, whatever their headers say
/// (tests 334, 499, 1484).
#[test]
fn some_responses_have_no_body() {
    let got = outcome(&fixture::reply(334), PLAIN);
    assert_eq!(
        (got.error, got.framing, got.close),
        (None, Some(Framing::None), false)
    );
    let head = asked(|a| a.head = true);
    let got = outcome(&fixture::reply(499), head);
    assert_eq!(
        (got.error, got.framing, got.size),
        (None, Some(Framing::None), Some(6)),
        "a HEAD's size is still announced"
    );
    let got = outcome(&fixture::reply(1484), head);
    assert_eq!(
        (got.error, got.framing, got.close),
        (None, Some(Framing::None), false)
    );
    let got = outcome(
        b"HTTP/1.1 304 Not\r\nContent-Length: 9\r\nTransfer-Encoding: gzip\r\n\r\n",
        PLAIN,
    );
    assert_eq!((got.error, got.framing), (None, Some(Framing::None)));
}

/// Content-Length is a number, or the same number listed or repeated
/// (tests 178, 394).
#[test]
fn a_length_is_one_number() {
    for test in [178, 394] {
        let got = outcome(&fixture::reply(test), PLAIN);
        assert_eq!(
            got.error,
            Some(HeadError::Framing(FramingError::BadLength)),
            "test {test}"
        );
    }
    let length = |values: &[&str]| {
        let mut reply = String::from("HTTP/1.1 200 OK\r\n");
        for v in values {
            reply += &format!("Content-Length:{v}\r\n");
        }
        reply += "\r\n";
        let got = outcome(reply.as_bytes(), PLAIN);
        got.error.map_or(Ok(got.framing), Err)
    };
    let bad = Err(HeadError::Framing(FramingError::BadLength));
    assert_eq!(length(&[" 6"]), Ok(Some(Framing::Length(6))));
    assert_eq!(length(&["6 , 6,6 "]), Ok(Some(Framing::Length(6))));
    assert_eq!(length(&["6", "\t6"]), Ok(Some(Framing::Length(6))));
    assert_eq!(length(&["6", "7"]), bad);
    assert_eq!(length(&["6,7"]), bad);
    assert_eq!(length(&["6x"]), bad);
    assert_eq!(length(&["+6"]), bad);
    assert_eq!(length(&["0"]), Ok(Some(Framing::None)));
    // Past what a size can be: ignored, and the connection closes.
    let got = outcome(
        b"HTTP/1.1 200 OK\r\nContent-Length: 9223372036854775808\r\n\r\n",
        PLAIN,
    );
    assert_eq!(
        (got.error, got.framing, got.close),
        (None, Some(Framing::UntilClose), true)
    );
    assert_eq!(got.notes, [Note::LengthOverflow]);
    let ignoring = asked(|a| a.ignore_length = true);
    let got = outcome(b"HTTP/1.1 200 OK\r\nContent-Length: junk\r\n\r\n", ignoring);
    assert_eq!((got.error, got.framing), (None, Some(Framing::UntilClose)));
}

/// A response points one place: a second `Location` that says something
/// else is refused, an empty one or the same again passed over, across
/// the request's interim heads too (test 772, `http_header_l`).
#[test]
fn a_response_has_one_location() {
    let got = outcome(&fixture::reply(772), PLAIN);
    assert_eq!(
        got.error,
        Some(HeadError::Framing(FramingError::MultipleLocations))
    );
    assert_eq!(
        got.error.map(|e| (e.to_string(), e.kind())),
        Some((
            "Multiple Location headers".into(),
            ErrorKind::WeirdServerReply
        ))
    );
    let head = |lines: &str| {
        let reply = format!("HTTP/1.1 200 OK\r\n{lines}Content-Length: 0\r\n\r\n");
        outcome(reply.as_bytes(), PLAIN).error
    };
    assert_eq!(head("Location: a\r\nLocation:  a \r\n"), None);
    assert_eq!(head("Location:\r\nLocation: a\r\nLocation: \r\n"), None);
    assert_eq!(
        head("location: a\r\nLOCATION: A\r\n"),
        Some(HeadError::Framing(FramingError::MultipleLocations))
    );
    let got = outcome(
        b"HTTP/1.1 100 Continue\r\nLocation: a\r\n\r\nHTTP/1.1 200 OK\r\nLocation: b\r\n\r\n",
        PLAIN,
    );
    assert_eq!(
        got.error,
        Some(HeadError::Framing(FramingError::MultipleLocations))
    );
}

/// A size past the limit fails at the head's end, after the blank line is
/// delivered; one too large to be a size fails at its header.
#[test]
fn a_size_past_the_limit_fails_at_the_head() {
    let limited = asked(|a| a.max_filesize = NonZeroU64::new(5));
    let got = outcome(
        b"HTTP/1.1 200 OK\r\nContent-Length: 6\r\n\r\nabcdef",
        limited,
    );
    assert_eq!(got.lines.len(), 3);
    let e = got.error.unwrap();
    assert_eq!(
        (e.to_string(), e.kind()),
        (
            "Maximum file size exceeded".into(),
            ErrorKind::FilesizeExceeded
        )
    );
    let got = outcome(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\n", limited);
    assert_eq!(got.error, None);
    let got = outcome(
        b"HTTP/1.1 200 OK\r\nContent-Length: 99999999999999999999\r\n\r\n",
        limited,
    );
    assert_eq!(
        (got.lines.len(), got.error),
        (1, Some(HeadError::Framing(FramingError::FileTooLarge)))
    );
}

/// What says the connection closes: HTTP/1.0 unless it keeps alive,
/// `Connection: close`, and an HTTP/1.1 body with nothing else to end it
/// (test 282).
#[test]
fn what_closes_the_connection() {
    let got = outcome(&fixture::reply(282), PLAIN);
    assert_eq!((got.framing, got.close), (Some(Framing::UntilClose), true));
    assert_eq!(got.notes, [Note::AssumeClose]);
    let h10 = Exchange {
        sent: HttpVersion::Http10,
        ..PLAIN
    };
    let got = outcome(b"HTTP/1.0 200 OK\r\nContent-Length: 1\r\n\r\n", h10);
    assert_eq!(
        (got.close, &got.notes[..]),
        (true, &[Note::Http10Close][..])
    );
    let got = outcome(
        b"HTTP/1.0 200 OK\r\nConnection: Keep-Alive\r\nContent-Length: 1\r\n\r\n",
        h10,
    );
    assert_eq!(
        (got.close, &got.notes[..]),
        (false, &[Note::Http10Close, Note::Http10KeepAlive][..])
    );
    let got = outcome(
        b"HTTP/1.1 200 OK\r\nConnection: Keep-Alive\r\nContent-Length: 1\r\n\r\n",
        PLAIN,
    );
    assert_eq!(
        (got.close, got.notes),
        (false, vec![]),
        "keep-alive is 1.0's"
    );
    let got = outcome(
        b"HTTP/1.1 200 OK\r\nConnection: x, close\r\nContent-Length: 1\r\n\r\n",
        PLAIN,
    );
    assert!(got.close);
    let head = asked(|a| a.head = true);
    let got = outcome(b"HTTP/1.1 200 OK\r\n\r\n", head);
    assert_eq!(
        (got.close, got.framing),
        (false, Some(Framing::None)),
        "a HEAD has no body to end"
    );
}

/// The bad lines of tests 262, 398, 415 and 2105, and 129's version.
#[test]
fn bad_heads_of_the_suite() {
    let bad = |test| outcome(&fixture::reply(test), PLAIN).error;
    assert_eq!(bad(262), Some(HeadError::BadLine(BadLine::Nul)));
    assert_eq!(bad(398), Some(HeadError::BadLine(BadLine::NoColon)));
    assert_eq!(bad(415), Some(HeadError::BadLine(BadLine::StrayCr)));
    assert_eq!(bad(2105), Some(HeadError::BadLine(BadLine::StrayCr)));
    assert_eq!(bad(129), Some(HeadError::BadSubversion));
    assert_eq!(bad(1473), None, "a blank-led line 2 with a colon");
}

/// The content type is kept, the last one given.
#[test]
fn the_content_type_is_kept() {
    let mut p = HeadParser::new(PLAIN);
    let mut input = &b"HTTP/1.1 200 OK\r\nContent-Type: a\r\nContent-Type:  \r\ncontent-type:  text/html \r\nTrailer: x\r\n\r\n"[..];
    while !p.is_done() {
        let (used, _) = p.feed(input, &mut 0).unwrap();
        input = &input[used..];
    }
    assert_eq!(p.meta().content_type(), Some(&b"text/html"[..]));
    assert!(p.meta().trailer());
}
