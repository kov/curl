//! Time conditions over HTTP: the header a request sends, and a document
//! the condition rules out ending the transfer as a 304 would.

use super::*;
use crate::options::{Condition, TimeCondition};

/// Sun, 12 Dec 1999 12:00:00 GMT.
const DEC_1999: i64 = 945_000_000;

fn since(when: Condition, time: i64) -> impl FnOnce(&mut Options) {
    move |o: &mut Options| o.time_condition = Some(TimeCondition { when, time })
}

/// A response whose document was last modified `modified`, with a body.
fn modified(modified: &str) -> Vec<u8> {
    format!("HTTP/1.1 200 OK\r\nLast-Modified: {modified}\r\nContent-Length: 6\r\n\r\n-foo-\n")
        .into_bytes()
}

const OLD: &str = "Wed, 13 Jun 1990 12:10:00 GMT";
const NEW: &str = "Fri, 13 Jun 2003 12:10:00 GMT";

/// The condition's header, with its time in GMT, unless the application
/// sends its own; a time `struct tm` cannot hold fails the request.
#[test]
fn a_time_condition_is_sent_as_its_header() {
    let header = |set: Box<dyn FnOnce(&mut Options)>| {
        let ran = run("/", &modified(NEW), false, set);
        let request = String::from_utf8(ran.request).unwrap();
        request
            .lines()
            .filter(|l| l.contains("odified"))
            .map(str::to_string)
            .collect::<Vec<_>>()
    };
    let at = "Sun, 12 Dec 1999 12:00:00 GMT";
    for (when, name) in [
        (Condition::ModifiedSince, "If-Modified-Since"),
        (Condition::UnmodifiedSince, "If-Unmodified-Since"),
        (Condition::LastModified, "Last-Modified"),
    ] {
        assert_eq!(
            header(Box::new(since(when, DEC_1999))),
            [format!("{name}: {at}")]
        );
    }
    assert!(header(Box::new(|_| {})).is_empty());
    let own = |o: &mut Options| {
        since(Condition::ModifiedSince, DEC_1999)(o);
        o.http.headers = UserHeaders::new([&b"If-Modified-Since:"[..]]).unwrap();
    };
    assert!(header(Box::new(own)).is_empty());
    let ran = run("/", OK, false, since(Condition::ModifiedSince, i64::MAX));
    assert_eq!(ran.result, Err(ErrorKind::BadFunctionArgument));
    assert!(ran.request.is_empty());
    assert!(ran.seen.text().iter().any(|l| l == "Invalid TIMEVALUE\n"));
}

/// A document older than asked for is not read: the transfer reports 304
/// and the condition unmet, and the connection goes with the body.
#[test]
fn an_older_document_ends_as_a_304() {
    let ran = run(
        "/",
        &modified(OLD),
        false,
        since(Condition::ModifiedSince, DEC_1999),
    );
    assert_eq!(ran.result, Ok(()));
    assert_eq!(ran.seen.body(), b"");
    assert_eq!(ran.easy.report().response_code(), Some(304));
    assert!(ran.easy.report().condition_unmet());
    let text = ran.seen.text();
    let notes = [
        "The requested document is not new enough\n",
        "Simulate an HTTP 304 response\n",
    ];
    let at = text.iter().position(|l| l == notes[0]).expect("said");
    assert_eq!(text[at + 1], notes[1]);
    assert!(
        text.last().unwrap().starts_with("shutting down connection"),
        "{text:?}"
    );
    // Not modified since: a newer one fails it.
    let ran = run(
        "/",
        &modified(NEW),
        false,
        since(Condition::UnmodifiedSince, DEC_1999),
    );
    assert_eq!(ran.seen.body(), b"");
    assert!(ran.easy.report().condition_unmet());
    assert!(
        ran.seen
            .text()
            .iter()
            .any(|l| l == "The requested document is not old enough\n")
    );
    // `Last-Modified` is checked as modified since.
    let ran = run(
        "/",
        &modified(OLD),
        false,
        since(Condition::LastModified, DEC_1999),
    );
    assert_eq!(ran.easy.report().response_code(), Some(304));
}

/// A document that meets the condition, one whose time is not known, a
/// condition at time 0 and a range asked for all read the body.
#[test]
fn a_document_that_meets_the_condition_is_read() {
    let read = |reply: &[u8], set: Box<dyn FnOnce(&mut Options)>| {
        let ran = run("/", reply, false, set);
        assert_eq!(ran.result, Ok(()));
        assert!(!ran.easy.report().condition_unmet());
        (ran.easy.report().response_code(), ran.seen.body())
    };
    let whole = (Some(200), b"-foo-\n".to_vec());
    let s = since(Condition::ModifiedSince, DEC_1999);
    assert_eq!(read(&modified(NEW), Box::new(s)), whole);
    let s = since(Condition::UnmodifiedSince, DEC_1999);
    assert_eq!(read(&modified(OLD), Box::new(s)), whole);
    let s = since(Condition::ModifiedSince, DEC_1999);
    assert_eq!(read(&modified("not a date"), Box::new(s)), whole);
    assert_eq!(
        read(OK, Box::new(since(Condition::ModifiedSince, DEC_1999))).0,
        Some(200)
    );
    let s = since(Condition::UnmodifiedSince, 0);
    assert_eq!(read(&modified(OLD), Box::new(s)), whole);
    let ranged = format!(
        "HTTP/1.1 206 Partial\r\nLast-Modified: {OLD}\r\nContent-Range: bytes 2-5/6\r\n\
         Content-Length: 4\r\n\r\noo-\n"
    );
    let resumed = |o: &mut Options| {
        since(Condition::ModifiedSince, DEC_1999)(o);
        o.resume = Some(Resume::At(NonZeroU64::new(2).unwrap()));
    };
    assert_eq!(
        read(ranged.as_bytes(), Box::new(resumed)),
        (Some(206), b"oo-\n".to_vec())
    );
}

/// A 304 from the server says the condition was not met, only when one
/// was asked.
#[test]
fn a_304_says_the_condition_was_unmet() {
    let not_modified = b"HTTP/1.1 304 Not Modified\r\nLast-Modified: x\r\n\r\n";
    let ran = run(
        "/",
        not_modified,
        false,
        since(Condition::ModifiedSince, DEC_1999),
    );
    assert!(ran.easy.report().condition_unmet());
    let ran = run("/", not_modified, false, |_| {});
    assert!(!ran.easy.report().condition_unmet());
}
