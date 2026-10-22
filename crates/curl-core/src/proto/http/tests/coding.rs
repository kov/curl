//! Content codings over HTTP: what `Accept-Encoding` asks for and how a
//! coded response is undone, with a decoder that writes each byte twice
//! standing in for a library's.

use super::*;
use crate::coding::{AcceptEncoding, Coding, Decoder, Decoders, Sink};

/// Each byte it is given, twice.
#[derive(Debug)]
struct Twice;

impl Decoder for Twice {
    fn decode(&mut self, input: &[u8], out: &mut dyn Sink) -> Result<(), ErrorKind> {
        let doubled: Vec<u8> = input.iter().flat_map(|&b| [b, b]).collect();
        out.write(&doubled)
    }
}

fn twice() -> Result<Box<dyn Decoder>, ErrorKind> {
    Ok(Box::new(Twice))
}

/// A handle that undoes `gzip` and `br` twice over.
fn decoding() -> Easy {
    let mut e = Easy::new();
    e.set_decoders(
        Decoders::none()
            .with(Coding::Brotli, twice)
            .with(Coding::Gzip, twice),
    );
    e
}

/// A GET by `e` from a server replying `reply`.
fn fetch(e: Easy, reply: &[u8], set: impl FnOnce(&mut Options)) -> Ran {
    let (mut m, talk, _) = server(&[reply], false);
    get_with(&mut m, e, "/", talk, set)
}

fn all(o: &mut Options) {
    o.http.accept_encoding = Some(AcceptEncoding::All);
}

const GZIPPED: &[u8] = b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\nContent-Encoding: gzip\r\n\r\nabc";

/// `Accept-Encoding` lists what the handle undoes in C's order, or what
/// the application gave; `identity` when nothing is undone; none unless
/// asked for, or where the application sends its own.
#[test]
fn accept_encoding_says_what_is_asked_for() {
    let line = |e: Easy, set: fn(&mut Options)| {
        let ran = fetch(e, OK, set);
        let request = String::from_utf8(ran.request).unwrap();
        request
            .lines()
            .find(|l| l.starts_with("Accept-Encoding"))
            .map(str::to_string)
    };
    assert_eq!(
        line(decoding(), all).as_deref(),
        Some("Accept-Encoding: gzip, br")
    );
    assert_eq!(
        line(Easy::new(), all).as_deref(),
        Some("Accept-Encoding: identity")
    );
    let given =
        |o: &mut Options| o.http.accept_encoding = Some(AcceptEncoding::Given(b"zz".to_vec()));
    assert_eq!(
        line(decoding(), given).as_deref(),
        Some("Accept-Encoding: zz")
    );
    assert_eq!(line(decoding(), |_| {}), None);
    let own = |o: &mut Options| {
        all(o);
        o.http.headers = UserHeaders::new([&b"Accept-Encoding: mine"[..]]).unwrap();
    };
    assert_eq!(
        line(decoding(), own).as_deref(),
        Some("Accept-Encoding: mine")
    );
    // The request's lines around it are C's.
    let ran = fetch(decoding(), OK, all);
    assert!(
        fixture::find(
            &ran.request,
            b"Accept: */*\r\nAccept-Encoding: gzip, br\r\n\r\n"
        )
        .is_some()
    );
}

/// A coded body is undone when codings were asked for, and delivered as
/// it came when they were not or the application wants it raw; the raw
/// trace sees it coded.
#[test]
fn a_coded_body_is_undone_when_asked_for() {
    let ran = fetch(decoding(), GZIPPED, all);
    assert_eq!(ran.result, Ok(()));
    assert_eq!(ran.seen.body(), b"aabbcc");
    assert_eq!(ran.seen.of("data").concat(), b"abc");
    assert_eq!(ran.easy.report().sizes().download(), 3);
    assert_eq!(fetch(decoding(), GZIPPED, |_| {}).seen.body(), b"abc");
    let raw = |o: &mut Options| {
        all(o);
        o.http.raw_content = true;
    };
    assert_eq!(fetch(decoding(), GZIPPED, raw).seen.body(), b"abc");
    // Codings stack, the last listed undone first; identity adds nothing.
    let stacked = b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\nContent-Encoding: gzip, identity\r\nContent-Encoding: BR\r\n\r\nx";
    assert_eq!(fetch(decoding(), stacked, all).seen.body(), b"xxxx");
}

/// A coding nothing undoes fails the body at its first byte, and only
/// then; more than five fail the response at once.
#[test]
fn codings_that_cannot_be_undone_fail() {
    let unknown = b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\nContent-Encoding: compress\r\n\r\nabc";
    let ran = fetch(decoding(), unknown, all);
    assert_eq!(ran.result, Err(ErrorKind::BadContentEncoding));
    assert!(
        ran.seen
            .text()
            .contains(&"Unrecognized content encoding type\n".to_string())
    );
    // One the handle has no decoder for, the same.
    let deflated = b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\nContent-Encoding: deflate\r\n\r\nabc";
    assert_eq!(
        fetch(decoding(), deflated, all).result,
        Err(ErrorKind::BadContentEncoding)
    );
    let empty = b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nContent-Encoding: compress\r\n\r\n";
    assert_eq!(fetch(decoding(), empty, all).result, Ok(()));
    let five = b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\nContent-Encoding: identity,identity,identity,identity,identity\r\n\r\nx";
    assert_eq!(fetch(decoding(), five, all).result, Ok(()));
    let six = b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\nContent-Encoding: identity,identity,identity\r\nContent-Encoding: gzip,gzip,gzip\r\n\r\nx";
    let ran = fetch(decoding(), six, all);
    assert_eq!(ran.result, Err(ErrorKind::BadContentEncoding));
    let said = "Reject response exceeding limit of 5 content encodings\n".to_string();
    assert!(ran.seen.text().contains(&said), "{:?}", ran.seen.text());
    assert!(ran.seen.body().is_empty());
}

/// Records what it takes, after pausing at its first piece.
#[derive(Clone, Default)]
struct PausesFirst {
    seen: Seen,
    paused: Rc<std::cell::Cell<bool>>,
}

impl WriteHandler for PausesFirst {
    fn write(&self, cx: &mut TransferCx<'_>, body: &[u8]) -> Write {
        if !self.paused.replace(true) {
            return Write::Pause;
        }
        self.seen.write(cx, body)
    }
}

impl HeaderHandler for PausesFirst {
    fn header(&self, cx: &mut TransferCx<'_>, line: &[u8], origin: HeaderOrigin) -> Write {
        self.seen.header(cx, line, origin)
    }
}

/// A trailer read with the body it follows, while a pause holds that body
/// still coded, comes after the body all the same.
#[test]
fn a_trailer_stays_behind_the_body_held_before_its_decoder() {
    let body = vec![b'z'; 10000];
    let mut reply =
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Encoding: gzip\r\n\r\n2710\r\n"
            .to_vec();
    reply.extend_from_slice(&body);
    reply.extend_from_slice(b"\r\n0\r\nT: after\r\n\r\n");
    let (mut m, _talk, _) = server(&[&reply], false);
    let mut e = decoding();
    let handler = PausesFirst::default();
    let o = e.options_mut();
    o.set_url(Some(format!("http://127.0.0.1:{PORT}/").as_bytes()))
        .unwrap();
    all(o);
    o.callbacks.write = Some(Handler::write(handler.clone()).unwrap());
    o.callbacks.header = Some(Handler::header(handler.clone()).unwrap());
    let id = m.add(e, (), &mut NoEvents).unwrap();
    for _ in 0..100 {
        m.perform(&mut NoEvents).unwrap();
        if let Some(msg) = m.info_read() {
            assert_eq!(msg.result, Ok(()));
            break;
        }
        m.pause(id, PauseRequest::CONT, &mut NoEvents).unwrap();
    }
    let order: Vec<&str> = handler.seen.0.borrow().iter().map(|(w, _)| *w).collect();
    let trailer = order
        .iter()
        .position(|w| *w == "trailer")
        .expect("a trailer");
    assert!(
        order[trailer + 1..].iter().all(|w| *w != "body"),
        "{order:?}"
    );
    assert_eq!(handler.seen.body(), vec![b'z'; 20000]);
}
