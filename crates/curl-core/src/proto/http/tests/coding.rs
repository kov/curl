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

/// `identity` blows nothing up: the body goes on as it is read, in up to
/// 16 KiB, the first read holding the head, not in the 4 KiB pieces of
/// what is held in front of a decoder that may (C's identity writer has
/// no `CURL_CW_FLAG_BLOWUP`).
#[test]
fn identity_holds_no_gate_in_front_of_the_body() {
    let mut reply =
        b"HTTP/1.1 200 OK\r\nContent-Length: 40000\r\nContent-Encoding: identity\r\n\r\n".to_vec();
    reply.extend_from_slice(&[b'i'; 40000]);
    let ran = fetch(decoding(), &reply, all);
    assert_eq!(ran.result, Ok(()));
    let writes: Vec<usize> = ran.seen.of("body").iter().map(Vec::len).collect();
    assert_eq!(writes, [16314, 16384, 7302]);
}

/// Pauses at the end of the head, and takes all after.
#[derive(Clone, Default)]
struct PausesAtHeadEnd(Seen);

impl HeaderHandler for PausesAtHeadEnd {
    fn header(&self, cx: &mut TransferCx<'_>, line: &[u8], origin: HeaderOrigin) -> Write {
        if line == b"\r\n" && !self.0.0.lock().unwrap().iter().any(|(w, _)| *w == "end") {
            self.0.0.lock().unwrap().push(("end", Vec::new()));
            return Write::Pause;
        }
        self.0.header(cx, line, origin)
    }
}

/// A coding nothing undoes fails the body at its first byte though a
/// handler paused before it: nothing holds the body in front of it, as
/// C's error writer is not one that blows up.
#[test]
fn an_unrecognized_coding_fails_while_paused() {
    let unknown = b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\nContent-Encoding: compress\r\n\r\nabc";
    let (mut m, _talk, _) = server(&[unknown], false);
    let mut e = decoding();
    let handler = PausesAtHeadEnd::default();
    let o = e.options_mut();
    o.set_url(Some(format!("http://127.0.0.1:{PORT}/").as_bytes()))
        .unwrap();
    all(o);
    o.callbacks.header = Some(Handler::header(handler.clone()).unwrap());
    m.add(Box::new(e), (), &mut NoEvents).unwrap();
    m.perform(&mut NoEvents).unwrap();
    // The connect started in the first pass is taken in the next.
    m.perform(&mut NoEvents).unwrap();
    let msg = m.info_read().expect("over, though paused");
    assert_eq!(msg.result, Err(ErrorKind::BadContentEncoding));
}

/// The decoders a handle has are shown by the codings they undo.
#[test]
fn decoders_show_their_codings() {
    let d = Decoders::none()
        .with(Coding::Zstd, twice)
        .with(Coding::Gzip, twice);
    assert_eq!(format!("{d:?}"), "[Gzip, Zstd]");
    assert_eq!(format!("{:?}", Decoders::none()), "[]");
}

/// Records what it takes, after pausing at its first piece.
#[derive(Clone, Default)]
struct PausesFirst {
    seen: Seen,
    paused: Arc<crate::test_cell::Cell<bool>>,
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
    let id = m.add(Box::new(e), (), &mut NoEvents).unwrap();
    // The whole reply read while paused, the body held still coded: the
    // transfer is not over while it holds it.
    for _ in 0..10 {
        m.perform(&mut NoEvents).unwrap();
    }
    assert!(m.info_read().is_none(), "over with its body held");
    for _ in 0..100 {
        m.pause(id, PauseRequest::CONT, &mut NoEvents).unwrap();
        m.perform(&mut NoEvents).unwrap();
        if let Some(msg) = m.info_read() {
            assert_eq!(msg.result, Ok(()));
            break;
        }
    }
    let order: Vec<&str> = handler
        .seen
        .0
        .lock()
        .unwrap()
        .iter()
        .map(|(w, _)| *w)
        .collect();
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

fn transfer_coded(o: &mut Options) {
    o.http.transfer_encoding = true;
}

/// Transfer codings asked for send `TE: gzip` and name it in
/// `Connection`, after the application's first: only where gzip can be
/// undone, and not where the application sends its own `TE`.
#[test]
fn te_asks_for_gzip_when_it_can_be_undone() {
    let lines = |e: Easy, set: fn(&mut Options)| {
        let ran = fetch(e, OK, set);
        let request = String::from_utf8(ran.request).unwrap();
        request
            .lines()
            .filter(|l| l.starts_with("TE") || l.starts_with("Connection"))
            .map(str::to_string)
            .collect::<Vec<_>>()
    };
    assert_eq!(
        lines(decoding(), transfer_coded),
        ["TE: gzip", "Connection: TE"]
    );
    assert!(lines(Easy::new(), transfer_coded).is_empty());
    assert!(lines(decoding(), |_| {}).is_empty());
    let kept = |o: &mut Options| {
        transfer_coded(o);
        o.http.headers = UserHeaders::new([&b"Connection: keep"[..], b"Connection: more"]).unwrap();
    };
    assert_eq!(
        lines(decoding(), kept),
        ["TE: gzip", "Connection: keep, TE", "Connection: more"]
    );
    let own = |o: &mut Options| {
        transfer_coded(o);
        o.http.headers = UserHeaders::new([&b"TE: mine"[..]]).unwrap();
    };
    assert_eq!(lines(decoding(), own), ["TE: mine"]);
}

/// A transfer coding is undone after the chunks, before the body is
/// counted: the size downloaded is the decoded one, as in C.
#[test]
fn a_transfer_coded_body_is_undone_before_it_is_counted() {
    let chunked =
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip, chunked\r\n\r\n3\r\nabc\r\n0\r\n\r\n";
    let ran = fetch(decoding(), chunked, transfer_coded);
    assert_eq!(ran.result, Ok(()));
    assert_eq!(ran.seen.body(), b"aabbcc");
    assert_eq!(ran.easy.report().sizes().download(), 6);
    // Without chunked, the close ends the body; with content codings too,
    // the transfer's are undone first.
    let closing = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip\r\nContent-Encoding: br\r\n\r\nx";
    let (mut m, talk, _) = server(&[closing], true);
    let ran = get_with(&mut m, decoding(), "/", talk, |o| {
        transfer_coded(o);
        all(o);
    });
    assert_eq!(ran.result, Ok(()));
    assert_eq!(ran.seen.body(), b"xxxx");
    assert_eq!(ran.easy.report().sizes().download(), 2);
}
