//! The tree read as C's reader reads it: the bytes, their pieces, the
//! size, and failures that end the read instead of the process.

use std::collections::VecDeque;
use std::convert::Infallible;
use std::num::NonZeroUsize;

use curl_alloc::TryArc;
use proptest::prelude::*;

use crate::deliver::{Lifts, Pause, PauseRequest};
use crate::handler::{Handler, Read, ReadHandler, Rewind, RewindFailed};
use crate::multi::TransferCx;
use crate::proto::http1::request::UserHeaders;

use super::read::{Calls, Escape, Got, MakeError, MimeReader};
use super::*;

/// A boundary of the letters from `A`, each draw one more.
fn boundary() -> Boundary {
    let mut n = 0u32;
    Boundary::draw(|| {
        n += 1;
        Ok::<_, Infallible>(n - 1)
    })
    .unwrap()
}

const LINE: &[u8] = b"------------------------ABCDEFGHIJKLMNOPQRSTUV";

/// A handler the tests' `Calls` stand in for: never called itself.
struct Unused;

impl ReadHandler for Unused {
    fn read(&self, _: &mut TransferCx<'_>, _: &mut [u8]) -> Read {
        unreachable!("the test's calls answer")
    }
}

impl Rewind for Unused {
    fn rewind(&self, _: &mut TransferCx<'_>) -> Result<(), RewindFailed> {
        unreachable!("the test's calls answer")
    }
}

/// What a handler answers, in the tests.
#[derive(Clone, Debug)]
enum Answer {
    Data(Vec<u8>),
    /// More than the room.
    TooMuch,
    Eof,
    Pause,
    Abort,
    Fail,
}

/// Each handler read answered from a queue, in order; then the end.
#[derive(Default)]
struct Script {
    answers: VecDeque<Answer>,
    /// The room of each read.
    rooms: Vec<usize>,
    rewinds: usize,
    rewind_fails: bool,
    /// The transfer's pause, which the test lifts.
    pause: Pause,
}

impl Script {
    fn new(answers: impl IntoIterator<Item = Answer>) -> Script {
        Script {
            answers: answers.into_iter().collect(),
            ..Script::default()
        }
    }

    /// The pause a handler asked for, lifted (`curl_easy_pause` with
    /// `CURLPAUSE_CONT`).
    fn lift(&mut self) {
        lift(&mut self.pause);
    }
}

fn lift(pause: &mut Pause) {
    pause.ask_send();
    pause.apply(PauseRequest::CONT);
}

impl Calls for Script {
    fn read(&mut self, _: &Handler<dyn ReadHandler>, buf: &mut [u8]) -> Read {
        self.rooms.push(buf.len());
        match self.answers.pop_front().unwrap_or(Answer::Eof) {
            // What does not fit is given at the next call.
            Answer::Data(mut d) => {
                let n = d.len().min(buf.len());
                buf[..n].copy_from_slice(&d[..n]);
                if n < d.len() {
                    self.answers.push_front(Answer::Data(d.split_off(n)));
                }
                NonZeroUsize::new(n).map_or(Read::Eof, Read::Data)
            }
            Answer::TooMuch => Read::Data(NonZeroUsize::new(buf.len() + 1).unwrap()),
            Answer::Eof => Read::Eof,
            Answer::Pause => Read::Pause,
            Answer::Abort => Read::Abort,
            Answer::Fail => Read::Fail,
        }
    }

    fn rewind(&mut self, _: &Handler<dyn Rewind>) -> Result<(), RewindFailed> {
        self.rewinds += 1;
        if self.rewind_fails {
            Err(RewindFailed)
        } else {
            Ok(())
        }
    }

    fn lifts(&self) -> Lifts {
        self.pause.lifts()
    }
}

fn bytes(b: &[u8]) -> Content {
    Content::Bytes(TryArc::try_new(b.to_vec()).unwrap())
}

fn named(name: &str, content: Content) -> Part {
    Part {
        name: Some(name.as_bytes().to_vec()),
        content,
        ..Part::default()
    }
}

fn callback(size: Option<u64>, rewind: bool) -> Content {
    Content::Read {
        handler: Handler::read(Unused).unwrap(),
        rewind: rewind.then(|| Handler::rewind(Unused).unwrap()),
        size,
    }
}

fn tree(parts: impl IntoIterator<Item = Part>) -> Mime {
    let mut m = Mime::new(boundary());
    for p in parts {
        m.add(p).unwrap();
    }
    m
}

fn reader(m: Mime) -> MimeReader {
    reader_with(m, &UserHeaders::NONE, Escape::Form)
}

fn reader_with(m: Mime, request: &UserHeaders, escaping: Escape) -> MimeReader {
    MimeReader::new(TryArc::try_new(m).unwrap(), request, escaping).unwrap()
}

/// Every read with `room`, as the pieces they gave, a pause lifted as it
/// comes; the last outcome if not the end.
fn pieces(r: &mut MimeReader, calls: &mut Script, room: usize) -> (Vec<Vec<u8>>, Option<Got>) {
    let mut out = Vec::new();
    let mut buf = vec![0u8; room];
    for _ in 0..100_000 {
        match r.next_for_test(&mut buf, calls) {
            Got::Bytes(0) => return (out, None),
            Got::Bytes(n) => out.push(buf[..n].to_vec()),
            Got::Pause => calls.lift(),
            got => return (out, Some(got)),
        }
    }
    panic!("a read that never ends");
}

fn contains(hay: &[u8], needle: &[u8]) -> bool {
    hay.windows(needle.len()).any(|w| w == needle)
}

fn all(r: &mut MimeReader, calls: &mut Script) -> Vec<u8> {
    let (p, end) = pieces(r, calls, 16384);
    assert_eq!(end, None);
    p.concat()
}

/// C's boundary: 24 dashes and characters drawn one per number, below the
/// largest multiple of 62; a number past it is drawn again.
#[test]
fn a_boundary_is_drawn_as_c_draws_it() {
    assert_eq!(boundary().line(), LINE);
    let mut draws = [u32::MAX, 61, 62].into_iter().cycle();
    let b = Boundary::draw(|| Ok::<_, Infallible>(draws.next().unwrap())).unwrap();
    assert_eq!(&b.line()[24..], b"9A9A9A9A9A9A9A9A9A9A9A");
    let r = Boundary::random().unwrap();
    assert!(r.line()[24..].iter().all(u8::is_ascii_alphanumeric));
}

/// A form of named fields: its head types it with the boundary, and the
/// body is what test 584 sends, its size known before.
#[test]
fn a_form_is_read_whole_and_sized() {
    let mut r = reader(tree([named("fake", bytes(b"party"))]));
    assert_eq!(
        r.head(),
        [[&b"Content-Type: multipart/form-data; boundary="[..], LINE].concat()]
    );
    let body = all(&mut r, &mut Script::default());
    let want = [
        b"--",
        LINE,
        b"\r\nContent-Disposition: form-data; name=\"fake\"\r\n\r\nparty\r\n--",
        LINE,
        b"--\r\n",
    ]
    .concat();
    assert_eq!(body, want);
    assert_eq!(r.size(), Some(156));
}

/// The application's `Content-Type` types the body in the library's
/// place; one naming another type makes it no form.
#[test]
fn the_application_types_the_body() {
    let headers = UserHeaders::new([&b"Content-Type: multipart/mixed"[..]]).unwrap();
    let r = reader_with(tree([named("a", bytes(b"1"))]), &headers, Escape::Form);
    assert_eq!(
        r.head(),
        [[&b"Content-Type: multipart/mixed; boundary="[..], LINE].concat()]
    );
    // Inside a mixed body a named part is an attachment.
    let mut r = r;
    let body = all(&mut r, &mut Script::default());
    assert!(
        contains(&body, b"Content-Disposition: attachment; name=\"a\"\r\n"),
        "{}",
        body.escape_ascii()
    );
}

/// Each part's headers: the disposition with its names quoted for a form,
/// the type given or guessed from a file name, the encoder; plain text
/// said only for a file; the application's own lines after the library's,
/// but its `Content-Type`, which is the type.
#[test]
fn a_part_s_headers_are_c_s() {
    let mut p = named("na\"me\r\n", bytes(b"x"));
    p.filename = Some(b"a.txt".to_vec());
    p.encoder = Some(Encoder::EightBit);
    p.headers = vec![b"X-A: 1".to_vec(), b"Content-Type: text/x".to_vec()];
    let mut plain = named("t", bytes(b"y"));
    plain.mime_type = None;
    let mut typed = named("u", bytes(b"z"));
    typed.mime_type = Some(b"text/plain".to_vec());
    let mut r = reader(tree([p, plain, typed]));
    let body = all(&mut r, &mut Script::default());
    let text = String::from_utf8(body.clone()).unwrap();
    assert!(text.contains(
        "Content-Disposition: form-data; name=\"na%22me%0D%0A\"; filename=\"a.txt\"\r\n\
         Content-Type: text/x\r\n\
         Content-Transfer-Encoding: 8bit\r\n\
         X-A: 1\r\n\r\nx\r\n"
    ));
    assert!(text.contains("Content-Disposition: form-data; name=\"t\"\r\n\r\ny\r\n"));
    assert!(text.contains("name=\"u\"\r\nContent-Type: text/plain\r\n\r\nz\r\n"));
    assert_eq!(r.size(), Some(body.len() as u64));
}

/// Quoted with backslashes, a name cannot carry a line break: the body
/// is refused before anything is read.
#[test]
fn backslash_quoting_refuses_a_line_break() {
    let r = MimeReader::new(
        TryArc::try_new(tree([named("a\"\\b", bytes(b"x"))])).unwrap(),
        &UserHeaders::NONE,
        Escape::Backslash,
    );
    let mut r = r.unwrap();
    let body = all(&mut r, &mut Script::default());
    assert!(contains(&body, b"name=\"a\\\"\\\\b\"\r\n"));
    let r = MimeReader::new(
        TryArc::try_new(tree([named("a\nb", bytes(b"x"))])).unwrap(),
        &UserHeaders::NONE,
        Escape::Backslash,
    );
    assert_eq!(r.err(), Some(MakeError::BadName));
}

/// Subparts are a `multipart/mixed` part with a boundary of their own,
/// their named parts attachments.
#[test]
fn subparts_nest_with_their_own_boundary() {
    let mut inner = Mime::new(Boundary::draw(|| Ok::<_, Infallible>(1)).unwrap());
    inner.add(named("i", bytes(b"in"))).unwrap();
    let mut r = reader(tree([named("outer", Content::Parts(inner))]));
    let body = all(&mut r, &mut Script::default());
    let inner_line = [&b"------------------------"[..], &[b'B'; 22]].concat();
    let want = [
        &b"--"[..],
        LINE,
        b"\r\nContent-Disposition: form-data; name=\"outer\"\r\n\
          Content-Type: multipart/mixed; boundary=",
        &inner_line,
        b"\r\n\r\n--",
        &inner_line,
        b"\r\nContent-Disposition: attachment; name=\"i\"\r\n\r\nin\r\n--",
        &inner_line,
        b"--\r\n\r\n--",
        LINE,
        b"--\r\n",
    ]
    .concat();
    assert_eq!(
        body.escape_ascii().to_string(),
        want.escape_ascii().to_string()
    );
    assert_eq!(r.size(), Some(body.len() as u64));
}

/// One fill calls out at most once: in-memory bytes and the headers go
/// with it as far as the room lets them, the next handler waits for the
/// next fill (`hasread`). These are the pieces of test 645's body.
#[test]
fn a_fill_calls_out_once() {
    let mut r = reader(tree([
        named("a", callback(None, false)),
        named("b", callback(None, false)),
        named("c", bytes(b"ccc")),
    ]));
    let mut calls = Script::new([
        Answer::Data(b"1".to_vec()),
        Answer::Data(b"2".to_vec()),
        Answer::Eof,
        Answer::Data(b"3".to_vec()),
        Answer::Eof,
    ]);
    let (p, end) = pieces(&mut r, &mut calls, 1024);
    assert_eq!(end, None);
    let heads = |name: &str| format!("Content-Disposition: form-data; name=\"{name}\"\r\n\r\n");
    let line = String::from_utf8(LINE.to_vec()).unwrap();
    let got: Vec<String> = p
        .iter()
        .map(|b| String::from_utf8(b.clone()).unwrap())
        .collect();
    assert_eq!(
        got,
        [
            format!("--{line}\r\n{}1", heads("a")),
            "2".to_string(),
            format!("\r\n--{line}\r\n{}", heads("b")),
            "3".to_string(),
            format!("\r\n--{line}\r\n{}ccc\r\n--{line}--\r\n", heads("c")),
        ]
    );
    assert_eq!(r.size(), None, "a callback without a size");
}

/// A part of known size is not read past it: the handler that filled it
/// is not asked again, so the next part's headers follow in the same fill
/// (test 668).
#[test]
fn a_part_of_known_size_ends_without_a_read() {
    let mut r = reader(tree([
        named("a", callback(Some(2), false)),
        named("b", bytes(b"b")),
    ]));
    let mut calls = Script::new([Answer::Data(b"xy".to_vec())]);
    let (p, end) = pieces(&mut r, &mut calls, 1024);
    assert_eq!(end, None);
    assert_eq!(p.len(), 1, "one fill");
    assert_eq!(calls.rooms.len(), 1, "one call");
    assert_eq!(r.size(), Some(p[0].len() as u64));
}

/// A body of known size that ends short is the read's failure, reported
/// by its caller with the count; one that ends at its size is whole.
#[test]
fn a_short_body_is_detected() {
    let mut r = reader(tree([named("a", callback(Some(5), false))]));
    let mut calls = Script::new([Answer::Data(b"ab".to_vec()), Answer::Eof]);
    let (p, end) = pieces(&mut r, &mut calls, 1024);
    assert_eq!(end, None, "the reader's caller weighs the size");
    let got: usize = p.iter().map(Vec::len).sum();
    assert!((got as u64) < r.size().unwrap());
}

/// The encoders, as C's encode: base64 in lines of 76, quoted-printable
/// with its escapes and soft breaks, 7bit refusing a byte past 127; the
/// size of base64 reckoned before, quoted-printable's unknown.
#[test]
fn encoders_encode_as_c_s() {
    let encoded = |e: Encoder, data: &[u8]| {
        let mut p = Part {
            encoder: Some(e),
            content: bytes(data),
            ..Part::default()
        };
        p.headers = vec![b"X: y".to_vec()];
        let mut r = reader(tree([p]));
        let size = r.size();
        let (pieces, end) = pieces(&mut r, &mut Script::default(), 16384);
        let body = pieces.concat();
        let start = body.windows(8).position(|w| w == b"X: y\r\n\r\n").unwrap() + 8;
        let stop = body.len() - (2 + 2 + LINE.len() + 4);
        (body[start..stop.max(start)].to_vec(), size, end, body.len())
    };
    let (b64, size, _, len) = encoded(Encoder::Base64, b"hello");
    assert_eq!(b64, b"aGVsbG8=");
    assert_eq!(size, Some(len as u64));
    let long = vec![b'x'; 120];
    let (b64, size, _, len) = encoded(Encoder::Base64, &long);
    let lines: Vec<&[u8]> = b64.split(|&b| b == b'\n').collect();
    assert_eq!(lines[0].len(), 77, "76 and a CR");
    assert_eq!(size, Some(len as u64));
    let (qp, size, _, _) = encoded(Encoder::QuotedPrintable, b"a=b \r\nc\td \r\x80");
    assert_eq!(qp, b"a=3Db=20\r\nc\td =0D=80");
    assert_eq!(size, None);
    let (qp, _, _, _) = encoded(Encoder::QuotedPrintable, &[b'q'; 80]);
    assert_eq!(qp, [&[b'q'; 75][..], b"=\r\n", &[b'q'; 5]].concat());
    // An escape that would cross the line's end starts the next.
    let (qp, _, _, _) = encoded(Encoder::QuotedPrintable, &[&[b'q'; 74][..], b"=x"].concat());
    assert_eq!(qp, [&[b'q'; 74][..], b"=\r\n=3Dx"].concat());
    let (_, _, end, _) = encoded(Encoder::SevenBit, b"ab\xffc");
    assert_eq!(end, Some(Got::Error));
    let (sevenbit, _, end, _) = encoded(Encoder::SevenBit, b"plain");
    assert_eq!((&sevenbit[..], end), (&b"plain"[..], None));
}

/// A read with little room reads ahead, so an encoder always has room for
/// a group: the bytes are the same as one large read's.
#[test]
fn little_room_gives_the_same_bytes() {
    let make = || {
        let p = Part {
            encoder: Some(Encoder::Base64),
            content: bytes(&[7u8; 200]),
            ..Part::default()
        };
        reader(tree([p, named("n", bytes(b"v"))]))
    };
    let whole = all(&mut make(), &mut Script::default());
    for room in 1..8 {
        let (p, end) = pieces(&mut make(), &mut Script::default(), room);
        assert_eq!(end, None);
        assert_eq!(p.concat(), whole, "room {room}");
    }
}

/// What the reader returns is the size C's `Curl_mime_read` would: the
/// bytes, or the values standing for an abort, a pause, a stop and an
/// error.
#[test]
fn what_a_read_got_is_c_s_size() {
    for (got, size) in [
        (Got::Bytes(7), 7),
        (Got::Funny(931), 931),
        (Got::Abort, 0x1000_0000),
        (Got::Pause, 0x1000_0001),
        (Got::Stop, 18_446_744_073_709_551_614),
        (Got::Error, 18_446_744_073_709_551_615),
    ] {
        assert_eq!(got.c_size(), size, "{got:?}");
    }
}

/// A handler's failures end the read with C's outcome, and stick: it is
/// not asked again.
#[test]
fn a_handler_s_failure_ends_the_read() {
    for (answer, want) in [
        (Answer::Abort, Got::Abort),
        (Answer::Fail, Got::Error),
        // One past the room left after the part's headers.
        (Answer::TooMuch, Got::Funny(931)),
    ] {
        let mut r = reader(tree([named("a", callback(None, false))]));
        let mut calls = Script::new([answer.clone()]);
        let (_, end) = pieces(&mut r, &mut calls, 1024);
        assert_eq!(end, Some(want), "{answer:?}");
        let mut buf = [0u8; 64];
        let again = r.next_for_test(&mut buf, &mut calls);
        assert_ne!(again, Got::Bytes(0), "{answer:?} sticks");
        assert_eq!(calls.rooms.len(), 1, "{answer:?}: asked once");
    }
}

/// A pause gives nothing and holds until the transfer's pause is lifted,
/// the handler not asked again before (`lastreadstatus`, `mime_unpause`).
/// One asked for after the headers in the same fill is the next fill's.
#[test]
fn a_pause_holds_until_lifted() {
    let mut r = reader(tree([named("a", callback(None, false))]));
    let mut calls = Script::new([Answer::Pause, Answer::Pause, Answer::Data(b"z".to_vec())]);
    let mut buf = [0u8; 1024];
    let Got::Bytes(head) = r.next_for_test(&mut buf, &mut calls) else {
        panic!("the headers go before the pause");
    };
    assert!(head > 0);
    assert_eq!(calls.rooms.len(), 1, "asked in the headers' fill");
    for asked in [1, 2] {
        assert_eq!(r.next_for_test(&mut buf, &mut calls), Got::Pause);
        assert_eq!(r.next_for_test(&mut buf, &mut calls), Got::Pause);
        assert_eq!(calls.rooms.len(), asked, "not asked while paused");
        calls.lift();
        if asked == 1 {
            assert_eq!(r.next_for_test(&mut buf, &mut calls), Got::Pause);
            assert_eq!(calls.rooms.len(), 2, "asked once lifted");
        }
    }
    assert_eq!(r.next_for_test(&mut buf, &mut calls), Got::Bytes(1));
    assert_eq!(buf[0], b'z');
}

/// A rewind starts the body over: bytes again, a handler through its
/// rewind; one without a rewind cannot once read. A new reader asks every
/// part's rewind, for parts read before it.
#[test]
fn a_rewind_starts_over() {
    let mut r = reader(tree([named("a", bytes(b"x"))]));
    let first = all(&mut r, &mut Script::default());
    assert!(r.restart_for_test(&mut Script::default()));
    assert_eq!(all(&mut r, &mut Script::default()), first);

    let mut r = reader(tree([named("a", callback(None, true))]));
    let mut calls = Script::new([Answer::Data(b"1".to_vec())]);
    assert!(r.start_for_test(&mut calls));
    assert_eq!(calls.rewinds, 0, "not reached before");
    let first = all(&mut r, &mut calls);
    calls.answers.push_back(Answer::Data(b"1".to_vec()));
    assert!(r.restart_for_test(&mut calls));
    assert_eq!(calls.rewinds, 1);
    assert_eq!(all(&mut r, &mut calls), first);
    calls.rewind_fails = true;
    assert!(!r.restart_for_test(&mut calls));

    let mut r = reader(tree([named("a", callback(None, false))]));
    all(&mut r, &mut Script::default());
    assert!(!r.restart_for_test(&mut Script::default()));
}

/// A file part is read when sent, its size known if it is regular; one
/// that is gone by then fails the read.
#[test]
fn a_file_is_read_as_it_is_sent() {
    let dir = std::env::temp_dir().join(format!("curl-mime-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("f.txt");
    std::fs::write(&path, b"file body").unwrap();
    let data = FileData::new(path.as_os_str().as_encoded_bytes()).unwrap();
    assert_eq!(data.size(), Some(9));
    let mut p = named("f", Content::File(data));
    p.filename = Some(b"f.txt".to_vec());
    let mut r = reader(tree([p]));
    let body = all(&mut r, &mut Script::default());
    let text = String::from_utf8(body.clone()).unwrap();
    assert!(text.contains("filename=\"f.txt\"\r\nContent-Type: text/plain\r\n\r\nfile body\r\n"));
    assert_eq!(r.size(), Some(body.len() as u64));
    // Gone before it is read.
    let data = FileData::new(path.as_os_str().as_encoded_bytes()).unwrap();
    std::fs::remove_file(&path).unwrap();
    let mut r = reader(tree([named("f", Content::File(data))]));
    let (_, end) = pieces(&mut r, &mut Script::default(), 1024);
    assert_eq!(end, Some(Got::Error));
    assert_eq!(
        FileData::new(path.as_os_str().as_encoded_bytes()).err(),
        Some(FileError::Unreadable)
    );
    std::fs::remove_dir(&dir).unwrap();
}

/// More than 40 levels is too large to make, as C's limit says.
#[test]
fn a_tree_too_deep_is_refused() {
    let nest = |levels: usize| {
        let mut m = tree([named("leaf", bytes(b"x"))]);
        for _ in 1..levels {
            m = tree([named("n", Content::Parts(m))]);
        }
        m
    };
    let deep = MimeReader::new(
        TryArc::try_new(nest(40)).unwrap(),
        &UserHeaders::NONE,
        Escape::Form,
    );
    assert_eq!(deep.err(), Some(MakeError::TooLarge));
    let ok = MimeReader::new(
        TryArc::try_new(nest(39)).unwrap(),
        &UserHeaders::NONE,
        Escape::Form,
    );
    assert!(ok.is_ok());
}

/// A part made of anything, its handler answering anything.
fn any_part(depth: u32) -> BoxedStrategy<(Part, Vec<Answer>)> {
    let answer = prop_oneof![
        3 => proptest::collection::vec(any::<u8>(), 1..20).prop_map(Answer::Data),
        1 => Just(Answer::TooMuch),
        1 => Just(Answer::Eof),
        1 => Just(Answer::Pause),
        1 => Just(Answer::Abort),
        1 => Just(Answer::Fail),
    ];
    let encoder = proptest::option::of(prop_oneof![
        Just(Encoder::Binary),
        Just(Encoder::EightBit),
        Just(Encoder::SevenBit),
        Just(Encoder::Base64),
        Just(Encoder::QuotedPrintable),
    ]);
    let leaf = (
        proptest::option::of(proptest::collection::vec(any::<u8>(), 0..8)),
        encoder,
        prop_oneof![
            proptest::collection::vec(any::<u8>(), 0..300).prop_map(|b| (Some(b), None)),
            (
                proptest::option::of(0u64..50),
                proptest::collection::vec(answer, 0..8)
            )
                .prop_map(|(size, answers)| (None, Some((size, answers)))),
        ],
    )
        .prop_map(|(name, encoder, (data, read))| {
            let (content, answers) = match (data, read) {
                (Some(d), _) => (bytes(&d), Vec::new()),
                (None, Some((size, answers))) => (callback(size, true), answers),
                (None, None) => (Content::None, Vec::new()),
            };
            (
                Part {
                    name,
                    encoder,
                    content,
                    ..Part::default()
                },
                answers,
            )
        });
    if depth == 0 {
        return leaf.boxed();
    }
    prop_oneof![
        3 => leaf,
        1 => proptest::collection::vec(any_part(depth - 1), 0..3).prop_map(|parts| {
            let mut answers = Vec::new();
            let mut m = Mime::new(boundary());
            for (p, a) in parts {
                m.add(p).unwrap();
                answers.extend(a);
            }
            (named("sub", Content::Parts(m)), answers)
        }),
    ]
    .boxed()
}

proptest! {
    #![proptest_config(crate::untrusted::config(64))]

    /// Whatever its parts and their handlers answer, a body is read to
    /// its end or to an error, never a panic or a loop, and a known size
    /// is the length read when nothing failed.
    #[test]
    fn a_malformed_part_is_an_error_not_a_panic(
        parts in proptest::collection::vec(any_part(2), 0..4),
        room in prop_oneof![1usize..8, 8usize..2000],
    ) {
        let mut m = Mime::new(boundary());
        let mut answers = Vec::new();
        for (p, a) in parts {
            m.add(p).unwrap();
            answers.extend(a);
        }
        let mut r = reader(m);
        let size = r.size();
        let mut calls = Script::new(answers);
        let (p, end) = pieces(&mut r, &mut calls, room);
        let read: usize = p.iter().map(Vec::len).sum();
        if end.is_none() && calls.rooms.is_empty() && let Some(size) = size {
            prop_assert_eq!(read as u64, size);
        }
        r.restart_for_test(&mut calls);
    }
}

/// Read whole, as `curl_formget` reads it, the tree is its headers, a
/// blank line and the body a request sends; a part a handler reads, which
/// no transfer is there to call, and a piece not taken whole fail it.
#[test]
fn a_tree_read_whole_starts_with_its_headers() {
    let form = || TryArc::try_new(tree([named("fake", bytes(b"party"))])).unwrap();
    let mut got = Vec::new();
    let mut pieces = 0;
    read_whole(form(), &mut |b| {
        pieces += 1;
        got.extend_from_slice(b);
        b.len()
    })
    .unwrap();
    let want = [
        &b"Content-Type: multipart/form-data; boundary="[..],
        LINE,
        b"\r\n\r\n--",
        LINE,
        b"\r\nContent-Disposition: form-data; name=\"fake\"\r\n\r\nparty\r\n--",
        LINE,
        b"--\r\n",
    ]
    .concat();
    assert_eq!(got, want);
    assert_eq!(pieces, 1, "bytes in memory are read in one fill");
    assert_eq!(
        read_whole(form(), &mut |b| b.len() - 1),
        Err(crate::error::ErrorKind::ReadError)
    );
    let handled = TryArc::try_new(tree([named("f", callback(Some(1), false))])).unwrap();
    assert_eq!(
        read_whole(handled, &mut |b| b.len()),
        Err(crate::error::ErrorKind::ReadError)
    );
}

fn new_reader(m: &TryArc<Mime>) -> MimeReader {
    MimeReader::new(m.clone(), &UserHeaders::NONE, Escape::Form).unwrap()
}

/// A part a request reached starts over before the next request reads
/// it, as C keeps in the part whether it was reached: a handler's part is
/// rewound only then, even if its handler was never called (a size of 0),
/// and a file that is not regular fails it. A part of nothing starts
/// over, where C fails (DIVERGENCE.md).
#[test]
fn a_part_reached_before_starts_over_as_c_s() {
    let m = TryArc::try_new(tree([named("a", callback(Some(0), true))])).unwrap();
    let mut calls = Script::default();
    let mut r = new_reader(&m);
    assert!(r.start_for_test(&mut calls));
    assert_eq!(calls.rewinds, 0, "not reached yet");
    all(&mut r, &mut calls);
    assert!(calls.rooms.is_empty(), "a size of 0 is not read");
    assert!(new_reader(&m).start_for_test(&mut calls));
    assert_eq!(calls.rewinds, 1, "reached, though never read");
    assert!(new_reader(&m).start_for_test(&mut calls));
    assert_eq!(calls.rewinds, 1, "started over since");

    let dev_null = FileData::new(b"/dev/null").unwrap();
    assert_eq!(dev_null.size(), None);
    let m = TryArc::try_new(tree([named("f", Content::File(dev_null))])).unwrap();
    let mut r = new_reader(&m);
    assert!(r.start_for_test(&mut calls));
    all(&mut r, &mut calls);
    assert!(
        !new_reader(&m).start_for_test(&mut calls),
        "a file that is not regular has no way back"
    );

    let m = TryArc::try_new(tree([named("n", Content::None)])).unwrap();
    all(&mut new_reader(&m), &mut calls);
    assert!(m.parts()[0].reached.get());
    assert!(
        new_reader(&m).start_for_test(&mut calls),
        "nothing starts over"
    );
}

/// A file that fails to read ends there if it is regular, as C's `fread`
/// ends it, for the body's size to tell; one that is not fails the read,
/// where C sends what came as all of it (DIVERGENCE.md).
#[test]
fn a_file_that_fails_to_read_ends_or_fails() {
    let dir = std::env::temp_dir();
    let dir = dir.as_os_str().as_encoded_bytes();
    let no_size = FileData::new(dir).unwrap();
    assert_eq!(no_size.size(), None);
    let mut r = reader(tree([named("d", Content::File(no_size))]));
    let (_, end) = pieces(&mut r, &mut Script::default(), 1024);
    assert_eq!(end, Some(Got::Error));
    // The same failure, in a file whose size is known.
    let sized = FileData {
        size: Some(5),
        ..FileData::new(dir).unwrap()
    };
    let mut r = reader(tree([named("d", Content::File(sized))]));
    let (p, end) = pieces(&mut r, &mut Script::default(), 1024);
    assert_eq!(end, None, "the part ends");
    let sent: usize = p.iter().map(Vec::len).sum();
    assert_eq!(r.size(), Some(sent as u64 + 5), "five bytes short");
}

/// A number at the largest multiple of 62 is drawn again, the one below
/// it kept; a draw that fails fails the boundary.
#[test]
fn a_boundary_redraws_from_the_largest_multiple() {
    let limit = u32::MAX - u32::MAX % 62;
    let mut draws = [limit, limit - 1].into_iter().cycle().take(100);
    let b = Boundary::draw(|| draws.next().ok_or(())).unwrap();
    assert_eq!(&b.line()[24..], [b'9'; 22]);
    let mut never = 0;
    let gone = Boundary::draw(|| {
        never += 1;
        if never > 30 { Err(()) } else { Ok(u32::MAX) }
    });
    assert_eq!(gone, Err(()));
}

/// A tree is as deep as its deepest subparts, 1 without any.
#[test]
fn a_tree_s_depth_counts_its_levels() {
    assert_eq!(tree([]).depth(), 1);
    assert_eq!(tree([named("a", bytes(b"x"))]).depth(), 1);
    let mid = tree([named("m", Content::Parts(tree([named("i", bytes(b"x"))])))]);
    assert_eq!(mid.depth(), 2);
    let top = tree([named("a", bytes(b"x")), named("s", Content::Parts(mid))]);
    assert_eq!(top.depth(), 3);
}

/// The encoders are named as `Content-Transfer-Encoding` names them, in
/// any case.
#[test]
fn an_encoder_is_found_by_its_name() {
    for (name, e) in [
        (&b"binary"[..], Some(Encoder::Binary)),
        (b"8BIT", Some(Encoder::EightBit)),
        (b"7bit", Some(Encoder::SevenBit)),
        (b"Base64", Some(Encoder::Base64)),
        (b"quoted-printable", Some(Encoder::QuotedPrintable)),
        (b"base6", None),
        (b"", None),
    ] {
        assert_eq!(Encoder::from_name(name), e, "{}", name.escape_ascii());
    }
}

/// The head lines kept for a probe are copies, and gone once cleared.
#[test]
fn sent_head_lines_are_kept_until_cleared() {
    let kept = SentHead::default();
    assert!(kept.lines().unwrap().is_empty());
    kept.keep(&[b"Content-Type: a".to_vec()]).unwrap();
    assert_eq!(kept.lines().unwrap(), [b"Content-Type: a".to_vec()]);
    kept.clear();
    assert!(kept.lines().unwrap().is_empty());
}

/// A file name's extension, in any case, suggests one of a few types
/// (`Curl_mime_contenttype`).
#[test]
fn a_file_name_suggests_its_type() {
    for (name, t) in [
        (&b"photo.GIF"[..], Some(&b"image/gif"[..])),
        (b"ab.png", Some(b"image/png")),
        (b"a.jpeg", Some(b"image/jpeg")),
        (b"index.html", Some(b"text/html")),
        (b".txt", Some(b"text/plain")),
        (b"gif", None),
        (b"a.txt.gz", None),
        (b"", None),
    ] {
        assert_eq!(content_type_for(name), t, "{}", name.escape_ascii());
    }
}

/// A file's type is guessed from the name it is sent as, else from its
/// path; one sent with a name no type is known for is an octet stream,
/// one without a name is not typed.
#[test]
fn a_file_part_is_typed_from_its_name_or_path() {
    let dir = std::env::temp_dir().join(format!("curl-mime-type-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let file = |name: &str| {
        let path = dir.join(name);
        std::fs::write(&path, b"x").unwrap();
        let path = path.as_os_str().as_encoded_bytes().to_vec();
        let data = FileData::new(&path).unwrap();
        assert_eq!(data.path(), path);
        data
    };
    let typed = |filename: Option<&str>, data: FileData| {
        let mut p = named("f", Content::File(data));
        p.filename = filename.map(|f| f.as_bytes().to_vec());
        let body = all(&mut reader(tree([p])), &mut Script::default());
        let text = String::from_utf8(body).unwrap();
        let at = text.find("Content-Type: ").map(|at| &text[at + 14..]);
        at.map(|t| t[..t.find('\r').unwrap()].to_string())
    };
    assert_eq!(typed(None, file("a.png")).as_deref(), Some("image/png"));
    assert_eq!(
        typed(Some("b.gif"), file("a.png")).as_deref(),
        Some("image/gif")
    );
    assert_eq!(
        typed(Some("b.bin"), file("a.dat")).as_deref(),
        Some("application/octet-stream")
    );
    assert_eq!(typed(None, file("a.dat")), None);
    // Bytes are typed from the name they are sent as only.
    let mut p = named("b", bytes(b"x"));
    p.filename = Some(b"b.bin".to_vec());
    let body = all(&mut reader(tree([p])), &mut Script::default());
    assert!(!contains(&body, b"Content-Type"));
    std::fs::remove_dir_all(&dir).unwrap();
}

/// A part's own line that is only a header's name, with no colon, names
/// no header: it is sent as given, and types nothing.
#[test]
fn a_line_without_a_colon_names_no_header() {
    let mut p = named("a", bytes(b"x"));
    p.headers = vec![b"Content-Type".to_vec(), b"Content-Type:".to_vec()];
    let body = all(&mut reader(tree([p])), &mut Script::default());
    assert!(
        contains(
            &body,
            b"name=\"a\"\r\nContent-Type: \r\nContent-Type\r\n\r\nx"
        ),
        "{}",
        body.escape_ascii()
    );
}

/// The application's `Content-Type` replaces the library's after a colon
/// or a semicolon, the blanks after it skipped (`Curl_checkheaders`).
#[test]
fn the_application_s_type_is_read_after_its_separator() {
    for line in [
        &b"Content-Type;  multipart/mixed"[..],
        b"Content-Type:multipart/mixed",
    ] {
        let headers = UserHeaders::new([line]).unwrap();
        let r = reader_with(tree([named("a", bytes(b"1"))]), &headers, Escape::Form);
        assert_eq!(
            r.head(),
            [[&b"Content-Type: multipart/mixed; boundary="[..], LINE].concat()],
            "{}",
            line.escape_ascii()
        );
    }
}

/// The size of a base64 part: four characters for each three bytes or
/// part of three, a CRLF between lines of 76; past C's limit against
/// overflowing a `curl_off_t`, unknown (`encoder_base64_size`).
#[test]
fn a_base64_part_s_size_is_c_s() {
    let size = |n: u64| {
        let p = Part {
            encoder: Some(Encoder::Base64),
            content: callback(Some(n), false),
            ..Part::default()
        };
        reader(tree([p])).size()
    };
    let none = size(0).unwrap();
    for (n, encoded) in [
        (1, 4),
        (3, 4),
        (4, 8),
        (56, 76),
        (57, 76),
        (58, 80 + 2),
        (114, 152 + 2),
        (115, 156 + 4),
    ] {
        assert_eq!(size(n), Some(none + encoded), "{n} bytes");
    }
    const MAX: u64 = ((i64::MAX as u64 / 78) * 76 / 4) * 3 - 3;
    assert_eq!(MAX, 6_740_156_488_470_797_697);
    let chars = 4 * (1 + (MAX - 1) / 3);
    assert_eq!(size(MAX), Some(none + chars + 2 * ((chars - 1) / 76)));
    assert_eq!(size(MAX + 1), None);
    // The bytes sent are as many, a line ending only between two.
    for n in [57, 58, 114] {
        let p = Part {
            encoder: Some(Encoder::Base64),
            content: bytes(&vec![b'z'; n]),
            ..Part::default()
        };
        let mut r = reader(tree([p]));
        let body = all(&mut r, &mut Script::default());
        assert_eq!(r.size(), Some(body.len() as u64), "{n} bytes");
    }
}

/// A file is read until it ends: one larger than a read's room in as many
/// reads as it takes, and one that ends short of the size it had ends the
/// part in the same fill, with no read after it.
#[test]
fn a_file_is_read_to_its_end() {
    let dir = std::env::temp_dir().join(format!("curl-mime-eof-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("big");
    let content: Vec<u8> = (0..3000u32).map(|i| (i % 251) as u8).collect();
    std::fs::write(&path, &content).unwrap();
    let data = FileData::new(path.as_os_str().as_encoded_bytes()).unwrap();
    let mut r = reader(tree([named("f", Content::File(data))]));
    let (p, end) = pieces(&mut r, &mut Script::default(), 1000);
    assert_eq!(end, None);
    let body = p.concat();
    assert!(contains(
        &body,
        &[&b"\r\n\r\n"[..], &content, b"\r\n--"].concat()
    ));
    assert_eq!(r.size(), Some(body.len() as u64));

    let path = dir.join("short");
    std::fs::write(&path, b"abc").unwrap();
    let data = FileData {
        size: Some(10),
        ..FileData::new(path.as_os_str().as_encoded_bytes()).unwrap()
    };
    let mut r = reader(tree([
        named("f", Content::File(data)),
        named("n", bytes(b"v")),
    ]));
    let (p, end) = pieces(&mut r, &mut Script::default(), 1024);
    assert_eq!(end, None);
    assert_eq!(p.len(), 1, "one fill");
    assert!(contains(&p[0], b"abc\r\n--"));
    assert!(p[0].ends_with(&[&b"v\r\n--"[..], LINE, b"--\r\n"].concat()));
    std::fs::remove_dir_all(&dir).unwrap();
}

/// Starting over starts over only the parts the reading reached: a part
/// not reached yet is not rewound, so one without a way back does not
/// fail it.
#[test]
fn a_rewind_leaves_a_part_not_reached() {
    let mut r = reader(tree([
        named("a", bytes(b"x")),
        named("b", callback(None, false)),
    ]));
    let mut buf = [0u8; 10];
    assert_eq!(
        r.next_for_test(&mut buf, &mut Script::default()),
        Got::Bytes(10)
    );
    let mut calls = Script::default();
    assert!(r.restart_for_test(&mut calls));
    assert_eq!(calls.rewinds, 0);
}

/// The data the C reader was run on: `binN` bytes of a pattern,
/// `ascii300` the alphabet over and over, and quoted-printable's cases.
fn oracle_data(name: &str) -> Vec<u8> {
    let pattern = |n: usize| (0..n).map(|i| ((i * 37 + 11) % 256) as u8).collect();
    match name {
        "bin57" => pattern(57),
        "bin114" => pattern(114),
        "bin200" => pattern(200),
        "bin1000" => pattern(1000),
        "bin3000" => pattern(3000),
        "qp1" => [
            &b"a=b \r\nc\td \r\x80"[..],
            &[b'q'; 74],
            b"=x \r\n",
            &[b'q'; 75],
            b"\r\n",
            &[b'q'; 76],
            b"\r\n",
            &[b'z'; 26],
            b"=\t",
        ]
        .concat(),
        "qp2" => vec![b'r'; 76],
        "hi" => b"ab\xffc".to_vec(),
        "ascii300" => (0..300).map(|i| b'a' + (i % 26) as u8).collect(),
        _ => unreachable!("{name}"),
    }
}

/// A handler that gives the data at most `chunk` bytes a call.
struct Fed {
    data: Vec<u8>,
    at: usize,
    chunk: usize,
}

impl Calls for Fed {
    fn read(&mut self, _: &Handler<dyn ReadHandler>, buf: &mut [u8]) -> Read {
        let n = (self.data.len() - self.at).min(self.chunk).min(buf.len());
        buf[..n].copy_from_slice(&self.data[self.at..self.at + n]);
        self.at += n;
        NonZeroUsize::new(n).map_or(Read::Eof, Read::Data)
    }

    fn rewind(&mut self, _: &Handler<dyn Rewind>) -> Result<(), RewindFailed> {
        unreachable!("not started over")
    }

    fn lifts(&self) -> Lifts {
        Lifts::default()
    }
}

#[derive(Clone, Copy, Debug)]
enum Src {
    Bytes,
    /// A handler of unknown size, `Fed` with this chunk.
    Fed(usize),
}

/// An encoder, the content, its data's name, whether a part follows, the
/// room, the size, the pieces' lengths and how the read ends.
type Case = (
    Option<Encoder>,
    Src,
    &'static str,
    bool,
    usize,
    Option<u64>,
    &'static str,
    Option<Got>,
);

/// An encoder and the name of the data it encodes.
type Kind = (Option<Encoder>, &'static str);

/// Lengths written `5x3 2` for 5, 5, 5, 2.
fn expand(lengths: &str) -> Vec<usize> {
    lengths
        .split(' ')
        .flat_map(|run| {
            let (n, times) = run.split_once('x').unwrap_or((run, "1"));
            std::iter::repeat_n(n.parse().unwrap(), times.parse().unwrap())
        })
        .collect()
}

/// The pieces C's reader gives a one-part tree (the part unnamed, with a
/// line `X: y` of its own, then with `trail` a part `n` of `v`), read
/// with each room: `lib/mime.c` built as the reference, its
/// `Curl_creader_set_mime` and `Curl_client_read` called with that room.
/// Where a fill ends follows from where each encoder stops for room and
/// for input, and at most one handler call each fill. The size is known
/// but for a handler of unknown size and quoted-printable.
#[test]
fn the_pieces_are_c_s() {
    #[rustfmt::skip]
    let cases: &[Case] = &[
        (Some(Encoder::Base64), Src::Bytes, "bin200", true, 1, Some(550), "1x550", None),
        (Some(Encoder::Base64), Src::Bytes, "bin200", true, 3, Some(550), "3x170 1 3x13", None),
        (Some(Encoder::Base64), Src::Bytes, "bin200", true, 5, Some(550), "5x25 4x19 2 4x19 2 4x19 2 4x10 5x30 1", None),
        (Some(Encoder::Base64), Src::Bytes, "bin200", true, 6, Some(550), "6x20 5 4x18 6 4x18 6 4x18 6 4x10 6x25 1", None),
        (Some(Encoder::Base64), Src::Bytes, "bin200", true, 7, Some(550), "7x17 6 4x18 6 4x18 6 4x18 6 4x10 7x21 4", None),
        (Some(Encoder::Base64), Src::Bytes, "bin200", true, 8, Some(550), "8x15 5 8x9 6 8x9 6 8x9 6 8x23 7", None),
        (Some(Encoder::Base64), Src::Bytes, "bin200", true, 12, Some(550), "12x10 9 12x6 10 12x5 10 12x6 10 12x15 7", None),
        (Some(Encoder::Base64), Src::Bytes, "bin200", true, 60, Some(550), "60x2 57 58x2 60x4 17", None),
        (Some(Encoder::Base64), Src::Bytes, "bin200", true, 63, Some(550), "63 62 60 62x3 63x2 53", None),
        (Some(Encoder::Base64), Src::Bytes, "bin200", true, 64, Some(550), "64 61 64 62x3 64x2 47", None),
        (Some(Encoder::Base64), Src::Bytes, "bin200", true, 100, Some(550), "100 97 100 98 100 55", None),
        (Some(Encoder::Base64), Src::Bytes, "bin200", true, 1024, Some(550), "550", None),
        (Some(Encoder::Base64), Src::Fed(7), "bin200", true, 5, None, "5x25 4x19 2 4x19 2 4x19 2 4x10 5x30 1", None),
        (Some(Encoder::Base64), Src::Fed(7), "bin200", true, 8, None, "8x15 5 8x9 6 8x9 6 8x9 6 8x4 4 8x19 3", None),
        (Some(Encoder::Base64), Src::Fed(7), "bin200", true, 12, None, "12x10 9 12x2 8x2 12 8x2 10 12 8 12 8x2 12 8 10 12 8x2 12 8x2 12 10 8 12 8 4 12x12 11", None),
        (Some(Encoder::Base64), Src::Fed(7), "bin200", true, 60, None, "60x2 13 8 12 8x2 12 8x2 14 8x2 12 8x2 12 8 10 12 8x2 12 8x2 12 10 8 12 8 4 60x2 35", None),
        (Some(Encoder::Base64), Src::Fed(7), "bin200", true, 100, None, "100 33 8 12 8x2 12 8x2 14 8x2 12 8x2 12 8 10 12 8x2 12 8x2 12 10 8 12 8 4 100 55", None),
        (Some(Encoder::Base64), Src::Fed(7), "bin200", true, 1024, None, "133 8 12 8x2 12 8x2 14 8x2 12 8x2 12 8 10 12 8x2 12 8x2 12 10 8 12 8 4 155", None),
        (Some(Encoder::QuotedPrintable), Src::Bytes, "qp1", true, 5, None, "5x29 4 3 5x13 3 5x3 4 5x36 3x2 5x30 4", None),
        (Some(Encoder::QuotedPrintable), Src::Bytes, "qp1", true, 6, None, "6x22 4x2 6x73 1", None),
        (Some(Encoder::QuotedPrintable), Src::Bytes, "qp1", true, 7, None, "7x21 5 7x9 5 7 5 7x49 4", None),
        (Some(Encoder::QuotedPrintable), Src::Bytes, "qp1", true, 8, None, "8x17 7 6 8x8 7 8x44 7", None),
        (Some(Encoder::QuotedPrintable), Src::Bytes, "qp1", true, 11, None, "11x13 9 11x7 10 11x16 10 11x14", None),
        (Some(Encoder::QuotedPrintable), Src::Bytes, "qp1", true, 77, None, "77 75 77x5 42", None),
        (Some(Encoder::QuotedPrintable), Src::Bytes, "qp1", true, 80, None, "80x2 79 80x4 20", None),
        (Some(Encoder::QuotedPrintable), Src::Bytes, "qp1", true, 1024, None, "579", None),
        (Some(Encoder::QuotedPrintable), Src::Fed(5), "qp1", true, 5, None, "5x29 4 3 5x13 3 5x3 4 5x30 4 5x5 4 3 5x30 4", None),
        (Some(Encoder::QuotedPrintable), Src::Fed(5), "qp1", true, 6, None, "6x22 4x2 6x8 5x6 6x7 5x26 3 6x2 5x4 6x25 4", None),
        (Some(Encoder::QuotedPrintable), Src::Fed(5), "qp1", true, 8, None, "8x17 7 6 8 6 5x11 8 5x2 8 6 5x28 3 7 5x5 8x19 2", None),
        (Some(Encoder::QuotedPrintable), Src::Fed(5), "qp1", true, 12, None, "12x11 8x2 10 5x12 8 5x2 9 5x29 3 7 5x5 12x12 10", None),
        (Some(Encoder::QuotedPrintable), Src::Fed(5), "qp1", true, 77, None, "77 63 8 10 5x12 8 5x2 9 5x29 3 7 5x5 77x2", None),
        (Some(Encoder::QuotedPrintable), Src::Fed(5), "qp1", true, 1024, None, "140 8 10 5x12 8 5x2 9 5x29 3 7 5x5 154", None),
        (Some(Encoder::QuotedPrintable), Src::Bytes, "qp2", false, 5, None, "5x53", None),
        (Some(Encoder::QuotedPrintable), Src::Bytes, "qp2", false, 8, None, "8x33 1", None),
        (Some(Encoder::QuotedPrintable), Src::Bytes, "qp2", false, 1024, None, "265", None),
        (Some(Encoder::SevenBit), Src::Bytes, "hi", false, 5, Some(181), "5x25", Some(Got::Error)),
        (Some(Encoder::SevenBit), Src::Bytes, "hi", false, 1024, Some(181), "125", Some(Got::Error)),
        (Some(Encoder::SevenBit), Src::Bytes, "ascii300", false, 5, Some(477), "5x95 2", None),
        (Some(Encoder::SevenBit), Src::Bytes, "ascii300", false, 100, Some(477), "100x4 77", None),
        (Some(Encoder::Binary), Src::Fed(300), "bin3000", false, 100, None, "100x31 79", None),
        (Some(Encoder::Binary), Src::Fed(300), "bin3000", false, 1024, None, "381 256x10 184 54", None),
        (None, Src::Fed(3000), "bin3000", false, 1024, None, "1024x3 18 54", None),
        (Some(Encoder::Base64), Src::Bytes, "bin57", false, 5, Some(255), "5x25 4x19 5x10 4", None),
        (Some(Encoder::Base64), Src::Bytes, "bin57", false, 8, Some(255), "8x15 5 8x16 2", None),
        (Some(Encoder::Base64), Src::Bytes, "bin57", false, 76, Some(255), "76 73 76 30", None),
        (Some(Encoder::Base64), Src::Bytes, "bin57", false, 1024, Some(255), "255", None),
        (Some(Encoder::Base64), Src::Fed(7), "bin57", false, 5, None, "5x25 4x19 5x10 4", None),
        (Some(Encoder::Base64), Src::Fed(7), "bin57", false, 8, None, "8x15 5 8x9 4 8x6 6", None),
        (Some(Encoder::Base64), Src::Fed(7), "bin57", false, 76, None, "76 57 8 12 8x2 12 8x2 4 54", None),
        (Some(Encoder::Base64), Src::Fed(7), "bin57", false, 1024, None, "133 8 12 8x2 12 8x2 4 54", None),
        (Some(Encoder::Base64), Src::Fed(57), "bin57", false, 5, None, "5x25 4x19 5x10 4", None),
        (Some(Encoder::Base64), Src::Fed(57), "bin57", false, 8, None, "8x15 5 8x16 2", None),
        (Some(Encoder::Base64), Src::Fed(57), "bin57", false, 76, None, "76 73 76 30", None),
        (Some(Encoder::Base64), Src::Fed(57), "bin57", false, 1024, None, "201 54", None),
        (Some(Encoder::Base64), Src::Bytes, "bin114", false, 5, Some(333), "5x25 4x19 2 4x19 5x10 4", None),
        (Some(Encoder::Base64), Src::Bytes, "bin114", false, 8, Some(333), "8x15 5 8x9 6 8x16 2", None),
        (Some(Encoder::Base64), Src::Bytes, "bin114", false, 76, Some(333), "76 73 74 76 34", None),
        (Some(Encoder::Base64), Src::Bytes, "bin114", false, 1024, Some(333), "333", None),
        (Some(Encoder::Base64), Src::Fed(7), "bin114", false, 5, None, "5x25 4x19 2 4x19 5x10 4", None),
        (Some(Encoder::Base64), Src::Fed(7), "bin114", false, 8, None, "8x15 5 8x9 6 8x9 4 8x6 6", None),
        (Some(Encoder::Base64), Src::Fed(7), "bin114", false, 76, None, "76 57 8 12 8x2 12 8x2 14 8x2 12 8x2 12 8 4 54", None),
        (Some(Encoder::Base64), Src::Fed(7), "bin114", false, 1024, None, "133 8 12 8x2 12 8x2 14 8x2 12 8x2 12 8 4 54", None),
        (Some(Encoder::Base64), Src::Fed(57), "bin114", false, 5, None, "5x25 4x19 2 4x19 5x10 4", None),
        (Some(Encoder::Base64), Src::Fed(57), "bin114", false, 8, None, "8x15 5 8x9 6 8x16 2", None),
        (Some(Encoder::Base64), Src::Fed(57), "bin114", false, 76, None, "76 73 74 76 34", None),
        (Some(Encoder::Base64), Src::Fed(57), "bin114", false, 1024, None, "201 78 54", None),
        (Some(Encoder::Binary), Src::Fed(1), "bin1000", false, 5, None, "5x25 1x1000 5x10 4", None),
        (Some(Encoder::Binary), Src::Fed(1), "bin1000", false, 7, None, "7x18 1x999 7x7 5", None),
        (Some(Encoder::Binary), Src::Fed(1), "bin1000", false, 50, None, "50x2 26 1x999 50 4", None),
        (Some(Encoder::Binary), Src::Fed(1), "bin1000", false, 100, None, "100 26 1x999 54", None),
        (Some(Encoder::Binary), Src::Fed(1), "bin1000", false, 255, None, "126 1x999 54", None),
        (Some(Encoder::Binary), Src::Fed(1), "bin1000", false, 256, None, "126 1x999 54", None),
        (Some(Encoder::Binary), Src::Fed(1), "bin1000", false, 257, None, "126 1x999 54", None),
        (Some(Encoder::Binary), Src::Fed(3), "bin1000", false, 5, None, "5x25 3x333 1 5x10 4", None),
        (Some(Encoder::Binary), Src::Fed(3), "bin1000", false, 7, None, "7x18 5 3x331 1 7x7 5", None),
        (Some(Encoder::Binary), Src::Fed(3), "bin1000", false, 50, None, "50x2 28 3x332 1 50 4", None),
        (Some(Encoder::Binary), Src::Fed(3), "bin1000", false, 100, None, "100 28 3x332 1 54", None),
        (Some(Encoder::Binary), Src::Fed(3), "bin1000", false, 255, None, "128 3x332 1 54", None),
        (Some(Encoder::Binary), Src::Fed(3), "bin1000", false, 256, None, "128 3x332 1 54", None),
        (Some(Encoder::Binary), Src::Fed(3), "bin1000", false, 257, None, "128 3x332 1 54", None),
        (Some(Encoder::Binary), Src::Fed(100), "bin1000", false, 5, None, "5x235 4", None),
        (Some(Encoder::Binary), Src::Fed(100), "bin1000", false, 7, None, "7x168 3", None),
        (Some(Encoder::Binary), Src::Fed(100), "bin1000", false, 50, None, "50x23 29", None),
        (Some(Encoder::Binary), Src::Fed(100), "bin1000", false, 100, None, "100x11 79", None),
        (Some(Encoder::Binary), Src::Fed(100), "bin1000", false, 255, None, "225 100x9 54", None),
        (Some(Encoder::Binary), Src::Fed(100), "bin1000", false, 256, None, "225 100x9 54", None),
        (Some(Encoder::Binary), Src::Fed(100), "bin1000", false, 257, None, "225 100x9 54", None),
        (Some(Encoder::Binary), Src::Fed(255), "bin1000", false, 5, None, "5x235 4", None),
        (Some(Encoder::Binary), Src::Fed(255), "bin1000", false, 7, None, "7x168 3", None),
        (Some(Encoder::Binary), Src::Fed(255), "bin1000", false, 50, None, "50x23 29", None),
        (Some(Encoder::Binary), Src::Fed(255), "bin1000", false, 100, None, "100x11 79", None),
        (Some(Encoder::Binary), Src::Fed(255), "bin1000", false, 255, None, "255x4 159", None),
        (Some(Encoder::Binary), Src::Fed(255), "bin1000", false, 256, None, "256x4 155", None),
        (Some(Encoder::Binary), Src::Fed(255), "bin1000", false, 257, None, "257x4 151", None),
        (Some(Encoder::Binary), Src::Fed(256), "bin1000", false, 5, None, "5x235 4", None),
        (Some(Encoder::Binary), Src::Fed(256), "bin1000", false, 7, None, "7x168 3", None),
        (Some(Encoder::Binary), Src::Fed(256), "bin1000", false, 50, None, "50x23 29", None),
        (Some(Encoder::Binary), Src::Fed(256), "bin1000", false, 100, None, "100x11 79", None),
        (Some(Encoder::Binary), Src::Fed(256), "bin1000", false, 255, None, "255x4 159", None),
        (Some(Encoder::Binary), Src::Fed(256), "bin1000", false, 256, None, "256x4 155", None),
        (Some(Encoder::Binary), Src::Fed(256), "bin1000", false, 257, None, "257x4 151", None),
        (Some(Encoder::Binary), Src::Fed(300), "bin1000", false, 5, None, "5x235 4", None),
        (Some(Encoder::Binary), Src::Fed(300), "bin1000", false, 7, None, "7x168 3", None),
        (Some(Encoder::Binary), Src::Fed(300), "bin1000", false, 50, None, "50x23 29", None),
        (Some(Encoder::Binary), Src::Fed(300), "bin1000", false, 100, None, "100x11 79", None),
        (Some(Encoder::Binary), Src::Fed(300), "bin1000", false, 255, None, "255x4 159", None),
        (Some(Encoder::Binary), Src::Fed(300), "bin1000", false, 256, None, "256x4 155", None),
        (Some(Encoder::Binary), Src::Fed(300), "bin1000", false, 257, None, "257x4 151", None),
    ];
    let mut bodies: Vec<(Kind, Vec<u8>)> = Vec::new();
    for &(encoder, src, data, trail, room, size, want, end) in cases {
        let what = format!("{encoder:?} {src:?} {data} room {room}");
        let content = match src {
            Src::Bytes => bytes(&oracle_data(data)),
            Src::Fed(_) => callback(None, false),
        };
        let part = Part {
            encoder,
            content,
            headers: vec![b"X: y".to_vec()],
            ..Part::default()
        };
        let mut parts = vec![part];
        if trail {
            parts.push(named("n", bytes(b"v")));
        }
        let mut r = reader(tree(parts));
        assert_eq!(r.size(), size, "{what}");
        let mut calls = Fed {
            data: oracle_data(data),
            at: 0,
            chunk: match src {
                Src::Bytes => 0,
                Src::Fed(chunk) => chunk,
            },
        };
        let mut got = Vec::new();
        let mut buf = vec![0u8; room];
        let last = loop {
            match r.next_for_test(&mut buf, &mut calls) {
                Got::Bytes(0) => break None,
                Got::Bytes(n) => got.push(buf[..n].to_vec()),
                other => break Some(other),
            }
        };
        let lengths: Vec<usize> = got.iter().map(Vec::len).collect();
        assert_eq!(lengths, expand(want), "{what}");
        assert_eq!(last, end, "{what}");
        // Every room gives the same bytes.
        let body = got.concat();
        match bodies.iter().find(|(k, _)| *k == (encoder, data)) {
            Some((_, first)) => assert_eq!(&body, first, "{what}"),
            None => bodies.push(((encoder, data), body)),
        }
    }
    // What C encoded, between the part's head and the next boundary.
    let encoded = |encoder, data| {
        let (_, body) = bodies.iter().find(|(k, _)| *k == (encoder, data)).unwrap();
        let start = body.windows(8).position(|w| w == b"X: y\r\n\r\n").unwrap() + 8;
        let end = start
            + body[start..]
                .windows(4)
                .position(|w| w == b"\r\n--")
                .unwrap();
        body[start..end].to_vec()
    };
    assert_eq!(
        encoded(Some(Encoder::Base64), "bin200")
            .escape_ascii()
            .to_string(),
        "CzBVep/E6Q4zWH2ix+wRNluApcrvFDleg6jN8hc8YYar0PUaP2SJrtP4HUJnjLHW+yBFao+02f4j\\r\\n\
         SG2St9wBJktwlbrfBClOc5i94gcsUXabwOUKL1R5nsPoDTJXfKHG6xA1Wn+kye4TOF2Cp8zxFjtg\\r\\n\
         harP9Bk+Y4it0vccQWaLsNX6H0RpjrPY/SJHbJG22wAlSm+Uud4DKE1yl7zhBitQdZq/5AkuU3id\\r\\n\
         wucMMVZ7oMXqDzRZfqPI7RI3XIGmy/AVOl+Eqc4="
    );
    let q = |n| "q".repeat(n);
    assert_eq!(
        encoded(Some(Encoder::QuotedPrintable), "qp1")
            .escape_ascii()
            .to_string(),
        format!(
            "a=3Db=20\\r\\nc\\td =0D=80{}=\\r\\n{}=3Dx=20\\r\\n{}\\r\\n{}\\r\\n{}=3D=09",
            q(65),
            q(9),
            q(75),
            q(76),
            "z".repeat(26)
        )
    );
    assert_eq!(
        encoded(Some(Encoder::QuotedPrintable), "qp2"),
        vec![b'r'; 76]
    );
    // 7bit sends what comes before a byte past 127, then fails.
    let (_, hi) = bodies
        .iter()
        .find(|(k, _)| *k == (Some(Encoder::SevenBit), "hi"))
        .unwrap();
    assert!(hi.ends_with(b"X: y\r\n\r\nab"), "{}", hi.escape_ascii());
}

/// Outside a form a part without a name has no disposition, whatever its
/// type; inside one it is `form-data` all the same.
#[test]
fn a_part_without_a_name_is_no_attachment() {
    let typed = |t: &[u8]| Part {
        mime_type: Some(t.to_vec()),
        content: bytes(b"x"),
        ..Part::default()
    };
    let headers = UserHeaders::new([&b"Content-Type: multipart/mixed"[..]]).unwrap();
    for t in [&b"a/b"[..], b"text/html", b"multipart/x"] {
        let mut r = reader_with(tree([typed(t)]), &headers, Escape::Form);
        let body = all(&mut r, &mut Script::default());
        let want = [&b"\r\nContent-Type: "[..], t, b"\r\n\r\nx\r\n"].concat();
        assert!(contains(&body, &want), "{}", body.escape_ascii());
        assert!(!contains(&body, b"Disposition"), "{}", body.escape_ascii());
    }
    let body = all(&mut reader(tree([typed(b"a/b")])), &mut Script::default());
    assert!(contains(
        &body,
        b"\r\nContent-Disposition: form-data\r\nContent-Type: a/b\r\n"
    ));
}

/// Started over in the middle of its encoding, a part is encoded afresh:
/// what was held for the encoder and its place on the line are dropped.
#[test]
fn a_rewind_drops_what_the_encoder_held() {
    let make = || {
        let p = Part {
            encoder: Some(Encoder::Base64),
            content: bytes(&oracle_data("bin200")),
            ..Part::default()
        };
        reader(tree([p]))
    };
    let whole = all(&mut make(), &mut Script::default());
    let mut r = make();
    let mut buf = [0u8; 150];
    for _ in 0..2 {
        let got = r.next_for_test(&mut buf, &mut Script::default());
        assert!(matches!(got, Got::Bytes(n) if n > 100), "{got:?}");
    }
    assert!(r.restart_for_test(&mut Script::default()));
    assert_eq!(all(&mut r, &mut Script::default()), whole);
}

/// The tree read whole starts over with its own headers.
#[test]
fn a_tree_read_whole_starts_over_with_its_headers() {
    let mut r =
        MimeReader::whole_for_test(TryArc::try_new(tree([named("a", bytes(b"x"))])).unwrap());
    let first = all(&mut r, &mut Script::default());
    assert!(first.starts_with(b"Content-Type: multipart/form-data; boundary="));
    assert!(r.restart_for_test(&mut Script::default()));
    assert_eq!(all(&mut r, &mut Script::default()), first);
}

/// A handler pausing on its second call, its first made by a fill that
/// it filled: the fill makes one call at most, so the pause is the next
/// fill's (`read_part_content`'s `hasread`). With room for 134 the
/// encoder holds a byte of the first call's, which the next fill gives
/// before the call that pauses: the pause is kept and given by the fill
/// after, which calls no handler (`lastreadstatus`). Each pause holds
/// until lifted. The pieces are the reference build's for these rooms.
#[test]
fn a_pause_after_a_full_fill_is_the_next_fill_s() {
    struct PausesSecond(Fed, usize, Pause);
    impl Calls for PausesSecond {
        fn read(&mut self, h: &Handler<dyn ReadHandler>, buf: &mut [u8]) -> Read {
            self.1 += 1;
            if self.1 == 2 {
                return Read::Pause;
            }
            self.0.read(h, buf)
        }

        fn rewind(&mut self, _: &Handler<dyn Rewind>) -> Result<(), RewindFailed> {
            unreachable!("not started over")
        }

        fn lifts(&self) -> Lifts {
            self.2.lifts()
        }
    }
    for (room, want) in [
        (134, "134 1 pause 10x19 54"),
        (135, "135 pause 10x19 54"),
        (136, "135 pause 10x19 54"),
    ] {
        let part = Part {
            encoder: Some(Encoder::Binary),
            content: callback(None, false),
            headers: vec![b"X: y".to_vec()],
            ..Part::default()
        };
        let mut r = reader(tree([part]));
        let fed = Fed {
            data: oracle_data("bin200"),
            at: 0,
            chunk: 10,
        };
        let mut calls = PausesSecond(fed, 0, Pause::default());
        let mut buf = vec![0u8; room];
        let mut got = Vec::new();
        loop {
            match r.next_for_test(&mut buf, &mut calls) {
                Got::Bytes(0) => break,
                Got::Bytes(n) => got.push(n.to_string()),
                Got::Pause => {
                    got.push("pause".to_string());
                    let asked = calls.1;
                    let again = r.next_for_test(&mut buf, &mut calls);
                    assert_eq!((again, calls.1), (Got::Pause, asked), "room {room}");
                    lift(&mut calls.2);
                }
                other => panic!("{other:?}"),
            }
        }
        let mut runs: Vec<String> = Vec::new();
        let mut i = 0;
        while i < got.len() {
            let n = got[i..].iter().take_while(|g| **g == got[i]).count();
            runs.push(if n > 1 {
                format!("{}x{n}", got[i])
            } else {
                got[i].clone()
            });
            i += n;
        }
        assert_eq!(runs.join(" "), want, "room {room}");
    }
}
