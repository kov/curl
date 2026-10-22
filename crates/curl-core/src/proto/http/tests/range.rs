//! Ranges over HTTP (`http_range`): what a request asks for with `Range`,
//! what an upload says it sends with `Content-Range`, and a response to a
//! range that is not a resume taken as it comes. Each was checked against
//! the C binary.

use super::*;

fn ranged(range: &'static [u8]) -> impl FnOnce(&mut Options) {
    move |o: &mut Options| o.range = Some(range.to_vec())
}

/// The request's lines that name a range.
fn range_lines(request: Vec<u8>) -> Vec<String> {
    String::from_utf8(request)
        .unwrap()
        .lines()
        .filter(|l| l.contains("Range"))
        .map(str::to_string)
        .collect()
}

const PARTIAL: &[u8] =
    b"HTTP/1.1 206 P\r\nContent-Range: bytes 1-3/9\r\nContent-Length: 3\r\n\r\nabc";

/// A GET and a HEAD ask for the range as given, where the request's
/// `Range` goes, unless the application sends its own.
#[test]
fn a_download_asks_for_its_range() {
    let ran = run("/", PARTIAL, false, ranged(b"0-10,12-15"));
    assert_eq!(ran.result, Ok(()));
    assert_eq!(
        ran.request,
        format!(
            "GET / HTTP/1.1\r\nHost: 127.0.0.1:{PORT}\r\nRange: bytes=0-10,12-15\r\n\
             User-Agent: curl/test\r\nAccept: */*\r\n\r\n"
        )
        .as_bytes()
    );
    assert_eq!(ran.seen.body(), b"abc");
    let ran = run("/", b"HTTP/1.1 206 P\r\n\r\n", true, |o| {
        ranged(b"1-3")(o);
        o.method = Method::Head;
    });
    assert_eq!(range_lines(ran.request), ["Range: bytes=1-3"]);
    let ran = run("/", PARTIAL, false, |o| {
        ranged(b"-101")(o);
        o.http.headers = UserHeaders::new([&b"Range: bytes=5-"[..]]).unwrap();
    });
    assert_eq!(range_lines(ran.request), ["Range: bytes=5-"]);
    // An application's resume point is asked for in place of its range.
    let ran = run("/", PARTIAL, false, |o| {
        ranged(b"7-9")(o);
        o.resume = Some(Resume::At(NonZeroU64::new(1).unwrap()));
    });
    assert_eq!(range_lines(ran.request), ["Range: bytes=1-"]);
}

/// An upload with a range says which part of the resource its body is,
/// its size the body's, C's -1 if unknown, and 0 while probing for
/// authentication; the application's own `Content-Range` replaces it.
#[test]
fn an_upload_names_its_range() {
    for method in [Method::Upload, Method::Post] {
        let ran = with_body(method, b"test\n", ranged(b"0-4"));
        assert_eq!(ran.result, Ok(()));
        assert_eq!(range_lines(ran.request), ["Content-Range: bytes 0-4/5"]);
    }
    let ran = with_body(Method::Upload, b"", |o| {
        ranged(b"0-4")(o);
        o.upload = pieces(&[b"abc"]);
        o.http.headers = UserHeaders::new([&b"Expect:"[..]]).unwrap();
    });
    assert_eq!(range_lines(ran.request), ["Content-Range: bytes 0-4/-1"]);
    let ran = with_body(Method::Upload, b"test\n", |o| {
        ranged(b"0-4")(o);
        o.http.headers = UserHeaders::new([&b"Content-Range: bytes 9-13/14"[..]]).unwrap();
    });
    assert_eq!(range_lines(ran.request), ["Content-Range: bytes 9-13/14"]);
}

/// A range that is no resume takes the response as it comes: a 200 with
/// the whole document is no failure, nor is a 416 spared `--fail`.
#[test]
fn a_response_to_a_range_is_taken_as_it_comes() {
    let ran = run(
        "/",
        b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nall\n",
        false,
        ranged(b"3-1000000"),
    );
    assert_eq!((ran.result, ran.seen.body()), (Ok(()), b"all\n".to_vec()));
    let not_satisfied = b"HTTP/1.1 416 No\r\nContent-Length: 4\r\n\r\nnope";
    let ran = run("/", not_satisfied, false, ranged(b"3-1000000"));
    assert_eq!((ran.result, ran.seen.body()), (Ok(()), b"nope".to_vec()));
    let ran = run("/", not_satisfied, false, |o| {
        ranged(b"3-1000000")(o);
        o.http.fail_on_error = true;
    });
    assert_eq!(ran.result, Err(ErrorKind::HttpReturnedError));
}
