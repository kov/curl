//! The tree read as C's reader reads it: the bytes, their pieces, the
//! size, and failures that end the read instead of the process.

use std::collections::VecDeque;
use std::convert::Infallible;
use std::num::NonZeroUsize;

use curl_alloc::TryArc;
use proptest::prelude::*;

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
}

impl Script {
    fn new(answers: impl IntoIterator<Item = Answer>) -> Script {
        Script {
            answers: answers.into_iter().collect(),
            ..Script::default()
        }
    }
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

/// Every read with `room`, as the pieces they gave; the last outcome if
/// not the end.
fn pieces(r: &mut MimeReader, calls: &mut Script, room: usize) -> (Vec<Vec<u8>>, Option<Got>) {
    let mut out = Vec::new();
    let mut buf = vec![0u8; room];
    for _ in 0..100_000 {
        match r.next_for_test(&mut buf, calls) {
            Got::Bytes(0) => return (out, None),
            Got::Bytes(n) => out.push(buf[..n].to_vec()),
            Got::Pause => {}
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

/// A handler's failures end the read with C's outcome, and stick: it is
/// not asked again.
#[test]
fn a_handler_s_failure_ends_the_read() {
    for (answer, want) in [
        (Answer::Abort, Got::Abort),
        (Answer::Fail, Got::Error),
        (Answer::TooMuch, Got::Funny),
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

/// A pause gives nothing and does not stick: the handler is asked again.
#[test]
fn a_pause_does_not_stick() {
    let mut r = reader(tree([named("a", callback(None, false))]));
    let mut calls = Script::new([Answer::Pause, Answer::Pause, Answer::Data(b"z".to_vec())]);
    let mut buf = [0u8; 1024];
    let Got::Bytes(head) = r.next_for_test(&mut buf, &mut calls) else {
        panic!("the headers go before the pause");
    };
    assert!(head > 0);
    assert_eq!(r.next_for_test(&mut buf, &mut calls), Got::Pause);
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
    assert_eq!(calls.rewinds, 1);
    let first = all(&mut r, &mut calls);
    calls.answers.push_back(Answer::Data(b"1".to_vec()));
    assert!(r.restart_for_test(&mut calls));
    assert_eq!(calls.rewinds, 2);
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
