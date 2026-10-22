use super::*;

/// Every line `input` gives out, each applied, until the answer ends or
/// the input runs out; the head's end with `auth_problem`.
fn lines(
    answer: &mut Answer,
    input: &[u8],
    auth_problem: bool,
) -> (Vec<Vec<u8>>, Vec<Applied>, usize) {
    let (mut got, mut applied, mut at) = (Vec::new(), Vec::new(), 0);
    loop {
        let (used, read) = answer.read(&input[at..]).unwrap();
        at += used;
        match read {
            Read::Line => {
                got.push(answer.line().to_vec());
                let a = answer.apply().unwrap();
                if a == Applied::End {
                    answer.end_head(auth_problem);
                }
                applied.push(a);
            }
            Read::More | Read::Done => return (got, applied, at),
        }
    }
}

/// As test 80's proxy sees it.
#[test]
fn renders_connect_as_c() {
    let mut out = Vec::new();
    let request = ConnectRequest {
        authority: b"test.80:8990",
        http10: true,
        proxy_authorization: Some(("Basic", b"eW91YXJlOnlvdXJzZWxm")),
        user_agent: Some(b""),
    };
    request.render(&mut out).unwrap();
    assert_eq!(
        out,
        b"CONNECT test.80:8990 HTTP/1.0\r\nHost: test.80:8990\r\n\
          Proxy-Authorization: Basic eW91YXJlOnlvdXJzZWxm\r\n\
          Proxy-Connection: Keep-Alive\r\n\r\n"
    );
    out.clear();
    let request = ConnectRequest {
        authority: b"[::1]:80",
        http10: false,
        proxy_authorization: None,
        user_agent: Some(b"curl/test"),
    };
    request.render(&mut out).unwrap();
    assert_eq!(
        out,
        b"CONNECT [::1]:80 HTTP/1.1\r\nHost: [::1]:80\r\nUser-Agent: curl/test\r\n\
          Proxy-Connection: Keep-Alive\r\n\r\n"
    );
}

/// A 200's head is read to its blank line and no further: what follows
/// is the tunnel's. Its length and coding are noted and ignored.
#[test]
fn reads_a_2xx_head_and_nothing_past_it() {
    let mut a = Answer::new();
    let input =
        b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nTransfer-Encoding: chunked\r\n\r\nHTTP/1.1";
    let (got, applied, used) = lines(&mut a, input, false);
    assert_eq!(got.len(), 4);
    assert_eq!(got[3], b"\r\n");
    assert_eq!(
        applied,
        [
            Applied::Nothing,
            Applied::Note(Note::IgnoringLength(200)),
            Applied::Note(Note::IgnoringEncoding(200)),
            Applied::End
        ]
    );
    assert_eq!(
        (used, a.code(), a.done()),
        (input.len() - 8, Some(200), true)
    );
}

/// Input that comes a byte at a time reads as input that comes whole;
/// a line that goes on is unfolded into one.
#[test]
fn reads_byte_by_byte_and_unfolds() {
    let input = b"HTTP/1.0 200 Fine\r\nX: a  \r\n \t b\r\nConnection: close\r\n\r\n";
    let mut a = Answer::new();
    let (whole, ..) = lines(&mut a, input, false);
    assert!(a.closes());
    let mut a = Answer::new();
    let mut bytes = Vec::new();
    for b in input {
        bytes.extend(lines(&mut a, std::slice::from_ref(b), false).0);
    }
    assert_eq!(bytes, whole);
    assert_eq!(whole[1], b"X: a b\r\n");
}

/// A 407's body is read and dropped by its length or its chunks, unless
/// authenticating went wrong, and nothing past it is read.
#[test]
fn drops_a_407_s_body() {
    let head =
        |extra: &str| format!("HTTP/1.1 407 Who\r\nProxy-Authenticate: Basic\r\n{extra}\r\n");
    let mut a = Answer::new();
    let input = head("Content-Length: 3\r\n") + "abcNEXT";
    let (_, applied, used) = lines(&mut a, input.as_bytes(), false);
    assert_eq!(applied[1], Applied::Challenge);
    assert_eq!(&input[used..], "NEXT");
    assert!(a.done() && !a.chunks_read());
    let mut a = Answer::new();
    let input = head("Transfer-Encoding: chunked\r\n") + "3\r\nabc\r\n0\r\n\r\nNEXT";
    let (_, _, used) = lines(&mut a, input.as_bytes(), false);
    assert_eq!(&input[used..], "NEXT");
    assert!(a.done() && a.chunks_read());
    let mut a = Answer::new();
    let input = head("Content-Length: 3\r\n") + "abc";
    let (_, _, used) = lines(&mut a, input.as_bytes(), true);
    assert_eq!(&input[used..], "abc", "not read with a problem");
    let mut a = Answer::new();
    let (_, _, used) = lines(&mut a, head("").as_bytes(), false);
    assert_eq!(used, head("").len());
    assert!(a.done(), "no length: the connection ends it");
}

/// A 407 saying both a length and chunks is decoded as chunks, though
/// the note names the length (test 1715).
#[test]
fn decodes_chunks_over_a_length() {
    let input = b"HTTP/1.1 407 Who\r\nContent-Length: 13\r\n\
                  Transfer-Encoding: chunked\r\n\r\nsome content\n";
    let mut a = Answer::new();
    let mut at = 0;
    let mut notes = Vec::new();
    let failed = loop {
        match a.read(&input[at..]) {
            Ok((used, Read::Line)) => {
                at += used;
                if a.apply().unwrap() == Applied::End {
                    notes.push(a.end_head(false));
                }
            }
            Ok((_, read)) => panic!("read {read:?} past bad chunks"),
            Err(e) => break e,
        }
    };
    assert_eq!(notes, [Some(Note::IgnoreBytes(13))]);
    assert_eq!(
        failed.said().map(|s| s.to_string()).as_deref(),
        Some("chunk hex-length char not a hex digit: 0x73")
    );
}

/// What C refuses, and how it says so.
#[test]
fn refuses_what_c_refuses() {
    let fails = |input: &[u8]| {
        let mut a = Answer::new();
        let mut at = 0;
        loop {
            let (used, read) = match a.read(&input[at..]) {
                Ok(read) => read,
                Err(e) => return Some(e),
            };
            at += used;
            if read != Read::Line {
                return None;
            }
            if let Err(e) = a.verify() {
                return Some(e);
            }
            match a.apply() {
                Ok(Applied::End) => {
                    a.end_head(false);
                }
                Ok(_) => {}
                Err(e) => return Some(e),
            }
        }
    };
    assert_eq!(
        fails(b"HTTP/1.1 2000 OK\r\n\r\n"),
        Some(AnswerError::BadStatus)
    );
    assert_eq!(
        fails(b"HTTP/1.2 200 OK\r\n\r\n"),
        Some(AnswerError::BadStatus)
    );
    assert_eq!(
        fails(b"HTTP/1.1 20 OK\r\n\r\n"),
        Some(AnswerError::BadStatus)
    );
    assert_eq!(fails(b"\r\n"), Some(AnswerError::NoHead));
    assert_eq!(
        fails(b"HTTP/1.1 200 OK\r\nX: a\0b\r\n\r\n"),
        Some(AnswerError::BadLine(BadLine::Nul))
    );
    assert_eq!(
        fails(b"HTTP/1.1 100 Go\r\nContent-Length: 1\r\n\r\n"),
        Some(AnswerError::LengthIn1xx(100))
    );
    assert_eq!(
        fails(b"HTTP/1.1 101 Go\r\nTransfer-Encoding: chunked\r\n\r\n"),
        Some(AnswerError::EncodingIn1xx(101))
    );
    assert_eq!(
        fails(b"HTTP/1.1 407 Who\r\nContent-Length: x\r\n\r\n"),
        Some(AnswerError::BadLength)
    );
    // A header with no colon passes, as C checks it before counting.
    assert_eq!(fails(b"HTTP/1.1 200 OK\r\nno colon\r\n\r\n"), None);
    let mut long = b"HTTP/1.1 200 OK\r\nX: ".to_vec();
    long.resize(long.len() + MAX_LINE, b'a');
    assert_eq!(fails(&long), Some(AnswerError::TooLarge));
    let said = |e: AnswerError| e.said().map(|s| s.to_string());
    assert_eq!(
        said(AnswerError::BadStatus).as_deref(),
        Some("Invalid response header")
    );
    assert_eq!(
        said(AnswerError::LengthIn1xx(100)).as_deref(),
        Some("Invalid Content-Length: in 100 response")
    );
    assert_eq!(said(AnswerError::NoHead), None);
}

/// A line read whole when the connection closes is given out.
#[test]
fn a_close_gives_out_the_line_read() {
    let mut a = Answer::new();
    assert_eq!(a.read(b"HTTP/1.1 200 OK\r\n").unwrap(), (17, Read::More));
    assert_eq!(a.closed(), Read::Line);
    assert_eq!(a.apply().unwrap(), Applied::Nothing);
    assert_eq!(a.closed(), Read::Done);
    assert!(!a.done());
}
