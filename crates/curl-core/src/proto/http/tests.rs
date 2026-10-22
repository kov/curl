use std::cell::RefCell;
use std::net::SocketAddr;
use std::num::NonZeroU64;
use std::rc::Rc;
use std::time::Duration;

use crate::conn::io::{Conversation, FakeNet, Peer};
use crate::easy::Easy;
use crate::error::ErrorKind;
use crate::handler::{
    DebugHandler, DebugKind, Handler, HeaderHandler, HeaderOrigin, Write, WriteHandler,
};
use crate::id::ArenaPolicy;
use crate::multi::{Env, Multi, NoEvents, PauseRequest, TransferCx, drive_to_completion};
use crate::options::{
    AuthMethods, Follow, MaxRedirects, Method, Options, PostRedir, Resume, UploadSource,
    UserHeaders,
};
use crate::proto::http1::{fixture, framing};
use crate::report::ResponseVersion;
use crate::time::{Clock as _, ManualClock};

/// Where the fake server listens.
const PORT: u16 = 8990;

/// One thing a transfer saw: which handler, or which kind of trace, and
/// the bytes.
type Saw = (&'static str, Vec<u8>);

/// What a transfer saw, in the order it saw it.
#[derive(Clone, Default)]
struct Seen(Rc<RefCell<Vec<Saw>>>);

impl Seen {
    fn of(&self, what: &str) -> Vec<Vec<u8>> {
        self.0
            .borrow()
            .iter()
            .filter(|(w, _)| *w == what)
            .map(|(_, b)| b.clone())
            .collect()
    }

    /// The trace's text lines, without the debug build's warning.
    fn text(&self) -> Vec<String> {
        self.of("text")
            .into_iter()
            .map(|l| String::from_utf8(l).unwrap())
            .filter(|l| !l.starts_with("!!! WARNING") && !l.starts_with("This is a debug build"))
            .collect()
    }

    /// Everything the body handler got, joined.
    fn body(&self) -> Vec<u8> {
        self.of("body").concat()
    }
}

impl WriteHandler for Seen {
    fn write(&self, _: &mut TransferCx<'_>, body: &[u8]) -> Write {
        self.0.borrow_mut().push(("body", body.to_vec()));
        Write::Accepted
    }
}

impl HeaderHandler for Seen {
    fn header(&self, _: &mut TransferCx<'_>, line: &[u8], origin: HeaderOrigin) -> Write {
        let what = match origin {
            HeaderOrigin::Trailer => "trailer",
            HeaderOrigin::Interim => "interim",
            HeaderOrigin::Header | HeaderOrigin::Connect => "header",
        };
        self.0.borrow_mut().push((what, line.to_vec()));
        Write::Accepted
    }
}

impl DebugHandler for Seen {
    fn debug(&self, _: &mut TransferCx<'_>, kind: DebugKind, data: &[u8]) {
        let what = match kind {
            DebugKind::Text => "text",
            DebugKind::HeaderIn => "in",
            DebugKind::HeaderOut => "out",
            DebugKind::DataIn => "data",
            DebugKind::DataOut => "dataout",
            _ => "other",
        };
        self.0.borrow_mut().push((what, data.to_vec()));
    }
}

/// What a run came to.
struct Ran {
    result: Result<(), ErrorKind>,
    /// What the server was sent.
    request: Vec<u8>,
    seen: Seen,
    easy: Easy,
}

/// A verbose GET of `/path` from a server replying `reply`, closing after
/// it if `close`, with the options `set` makes.
fn run(path: &str, reply: &[u8], close: bool, set: impl FnOnce(&mut Options)) -> Ran {
    let (mut m, talk, clock) = server(&[reply], close);
    let start = clock.now();
    let ran = get(&mut m, path, talk, set);
    // A run over a peer that answers at once takes no time: a wait that
    // timed out instead would have moved the clock on.
    assert_eq!(clock.now(), start, "the transfer waited on its socket");
    ran
}

/// A multi whose network has a server at `PORT` replying `replies` in
/// turn on one connection, closing after them if `close`.
fn server(replies: &[&[u8]], close: bool) -> (Multi, Conversation, ManualClock) {
    let clock = ManualClock::new().unwrap();
    let at = SocketAddr::from(([127, 0, 0, 1], PORT));
    let talk = Conversation::replies(replies, close);
    let net = FakeNet::new(clock.clone())
        .with_peer(at, Peer::Accepts)
        .with_conversation(at, talk.clone());
    let env = Env {
        clock: Box::new(clock.clone()),
        net: Box::new(net),
        arena: ArenaPolicy::new(16, 0).unwrap(),
        waker: None,
    };
    (Multi::new(env).unwrap(), talk, clock)
}

/// A verbose GET of `/path` on `m`, whose server is `talk`.
fn get(m: &mut Multi, path: &str, talk: Conversation, set: impl FnOnce(&mut Options)) -> Ran {
    get_with(m, Easy::new(), path, talk, set)
}

/// As `get`, by the handle `e`.
fn get_with(
    m: &mut Multi,
    mut e: Easy,
    path: &str,
    talk: Conversation,
    set: impl FnOnce(&mut Options),
) -> Ran {
    let url = format!("http://127.0.0.1:{PORT}{path}");
    let seen = Seen::default();
    let o = e.options_mut();
    o.set_url(Some(url.as_bytes())).unwrap();
    o.output.verbose = true;
    // A transfer that hangs fails, rather than the test.
    o.limits.total = crate::time::TimeLimit::from_millis(10_000);
    o.http.user_agent = Some(b"curl/test".to_vec());
    o.callbacks.write = Some(Handler::write(seen.clone()).unwrap());
    o.callbacks.header = Some(Handler::header(seen.clone()).unwrap());
    o.callbacks.debug = Some(Handler::debug(seen.clone()).unwrap());
    set(o);
    let id = m.add(e, (), &mut NoEvents).unwrap();
    let result = drive_to_completion(m, id, &mut NoEvents).unwrap();
    let easy = m.remove(id, &mut NoEvents).unwrap().easy;
    Ran {
        result,
        request: talk.received(),
        seen,
        easy,
    }
}

/// The request test `test` expects, its `%VERSION` our user agent's.
fn request_of(path: &str) -> Vec<u8> {
    format!(
        "GET {path} HTTP/1.1\r\nHost: 127.0.0.1:{PORT}\r\nUser-Agent: curl/test\r\nAccept: */*\r\n\r\n"
    )
    .into_bytes()
}

/// Test 1: the head goes, the response's head comes to the header
/// handler line by line and its body to the write handler, and the
/// connection closes as the response says.
#[test]
fn a_get_is_sent_and_its_response_delivered() {
    let ran = run("/1", &fixture::reply(1), false, |_| {});
    assert_eq!(ran.result, Ok(()));
    assert_eq!(ran.request, request_of("/1"));
    assert_eq!(
        ran.seen.of("out").concat(),
        request_of("/1"),
        "traced as sent"
    );
    assert_eq!(ran.seen.body(), b"-foo-\n");
    let reply = fixture::reply(1);
    let head_end = fixture::find(&reply, b"\r\n\r\n").unwrap() + 4;
    assert_eq!(ran.seen.of("header").concat(), &reply[..head_end]);
    assert_eq!(ran.seen.of("in"), ran.seen.of("header"), "each line traced");
    assert_eq!(ran.seen.of("header").len(), 11);
    let text = ran.seen.text();
    assert_eq!(text[0], format!("  Trying 127.0.0.1:{PORT}...\n"));
    assert_eq!(
        &text[2..],
        [
            "Request completely sent off\n",
            "shutting down connection #0\n"
        ]
    );
    let sizes = ran.easy.report().sizes();
    assert_eq!((sizes.download(), sizes.download_expected()), (6, Some(6)));
}

/// A line ending the head is whatever runs from a CR or LF to the LF:
/// stray bytes before it are delivered with it, as C delivers them, and
/// the body follows.
#[test]
fn a_long_line_ending_the_head_is_delivered_whole() {
    let ran = run(
        "/",
        b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\rX\r\nabc",
        false,
        |_| {},
    );
    assert_eq!(ran.result, Ok(()));
    assert_eq!(
        ran.seen.of("header"),
        [
            &b"HTTP/1.1 200 OK\r\n"[..],
            b"Content-Length: 3\r\n",
            b"\rX\r\n"
        ]
    );
    assert_eq!(ran.seen.body(), b"abc");
}

/// Takes the body, pausing at its first piece.
#[derive(Clone, Default)]
struct PausesOnce {
    got: Rc<RefCell<Vec<u8>>>,
    paused: Rc<std::cell::Cell<bool>>,
}

impl WriteHandler for PausesOnce {
    fn write(&self, _: &mut TransferCx<'_>, body: &[u8]) -> Write {
        if !self.paused.replace(true) {
            return Write::Pause;
        }
        self.got.borrow_mut().extend_from_slice(body);
        Write::Accepted
    }
}

/// A body whose last piece is paused is held, not lost: the transfer is
/// not over until it is delivered (`multi.c`, test 1540's rule).
#[test]
fn a_paused_last_piece_waits_to_be_delivered() {
    for reply in [
        &b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nabc"[..],
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n0\r\n\r\n",
    ] {
        let (mut m, _talk, _clock) = server(&[reply], false);
        let mut e = Easy::new();
        let url = format!("http://127.0.0.1:{PORT}/");
        let writer = PausesOnce::default();
        let o = e.options_mut();
        o.set_url(Some(url.as_bytes())).unwrap();
        o.callbacks.write = Some(Handler::write(writer.clone()).unwrap());
        let id = m.add(e, (), &mut NoEvents).unwrap();
        for _ in 0..4 {
            m.perform(&mut NoEvents).unwrap();
        }
        assert!(writer.paused.get(), "paused");
        assert!(m.info_read().is_none(), "not over while output is held");
        m.pause(id, PauseRequest::CONT, &mut NoEvents).unwrap();
        let result = drive_to_completion(&mut m, id, &mut NoEvents).unwrap();
        assert_eq!(result, Ok(()));
        assert_eq!(*writer.got.borrow(), b"abc", "{reply:?}");
    }
}

/// A response that keeps the connection leaves it in the pool.
#[test]
fn a_kept_connection_is_left_intact() {
    let reply = b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nabc";
    let ran = run("/", reply, false, |_| {});
    assert_eq!((ran.result, ran.seen.body()), (Ok(()), b"abc".to_vec()));
    assert_eq!(
        ran.seen.text().last().unwrap(),
        &format!("Connection #0 to host 127.0.0.1:{PORT} left intact\n")
    );
}

/// The ways a response can end, each as the C tool showed.
#[test]
fn responses_end_as_c_ends_them() {
    // The reply, whether the server closes after it, the result, the body
    // and a line the trace must have.
    type Case<'a> = (&'a [u8], bool, Result<(), ErrorKind>, &'a [u8], &'a str);
    let cases: &[Case<'_>] = &[
        // No size, no chunks, no close: the end is the close.
        (
            b"HTTP/1.1 200 OK\r\n\r\n-foo-\n",
            true,
            Ok(()),
            b"-foo-\n",
            "shutting down connection #0\n",
        ),
        (
            b"HTTP/1.1 200 OK\r\nContent-Length: 6\r\n\r\nabc",
            true,
            Err(ErrorKind::PartialFile),
            b"abc",
            "end of response with 3 bytes missing\n",
        ),
        (
            b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nabcdef",
            false,
            Ok(()),
            b"abc",
            "Excess found writing body: excess = 3, size = 3, maxdownload = 3, bytecount = 3\n",
        ),
        (
            b"HTTP/1.1 100 Continue\r\n\r\n",
            true,
            Err(ErrorKind::GotNothing),
            b"",
            "Empty reply from server\n",
        ),
        // Not cut short: the connection is shut down, not terminated.
        (
            b"HTTP/1.1 100 Continue\r\n\r\n",
            true,
            Err(ErrorKind::GotNothing),
            b"",
            "shutting down connection #0\n",
        ),
        (
            b"",
            true,
            Err(ErrorKind::GotNothing),
            b"",
            "Empty reply from server\n",
        ),
        (
            b"HTTP/1.1 200 OK\r\n",
            true,
            Ok(()),
            b"",
            "shutting down connection #0\n",
        ),
        (
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc",
            true,
            Err(ErrorKind::PartialFile),
            b"abc",
            "transfer closed with outstanding read data remaining\n",
        ),
        (
            b"HTTP/1.1 200 OK\r\nContent-Length: 6\r\nFunny-head: swsclose\r\n",
            true,
            Err(ErrorKind::PartialFile),
            b"",
            "transfer closed with 6 bytes remaining to read\n",
        ),
    ];
    for &(reply, close, result, body, says) in cases {
        let ran = run("/", reply, close, |_| {});
        let shown = String::from_utf8_lossy(reply);
        assert_eq!(
            (ran.result, &ran.seen.body()[..]),
            (result, body),
            "{shown}"
        );
        assert!(
            ran.seen.text().iter().any(|l| l == says),
            "{shown}: {:?}",
            ran.seen.text()
        );
    }
}

/// A line held to see whether the next continues it is delivered at the
/// end, after the failure the end found (`Curl_http_done`).
#[test]
fn a_held_line_is_delivered_at_the_end() {
    let reply = b"HTTP/1.1 200 OK\r\nContent-Length: 6\r\nFunny-head: swsclose\r\n";
    let ran = run("/", reply, true, |_| {});
    assert_eq!(ran.result, Err(ErrorKind::PartialFile));
    assert_eq!(
        ran.seen.of("header").last().unwrap(),
        b"Funny-head: swsclose\r\n"
    );
    let order: Vec<_> = ran
        .seen
        .0
        .borrow()
        .iter()
        .filter(|(w, _)| matches!(*w, "text" | "header"))
        .map(|(w, b)| (*w, String::from_utf8_lossy(b).into_owned()))
        .collect();
    let failed = order
        .iter()
        .position(|(_, l)| l.starts_with("transfer closed with"))
        .unwrap();
    assert_eq!(order[failed + 1].1, "Funny-head: swsclose\r\n");
    // A line never ended is traced, but no handler takes it.
    let ran = run("/", b"HTTP/1.1 200", true, |_| {});
    assert_eq!(ran.result, Err(ErrorKind::GotNothing));
    assert_eq!(ran.seen.of("in"), [b"HTTP/1.1 200".to_vec()]);
    assert_eq!(ran.seen.of("header"), Vec::<Vec<u8>>::new());
}

/// Chunks are decoded into the body and their trailers delivered as
/// trailers (test 266); raw, they go as they came (test 326).
#[test]
fn chunks_are_read_to_their_end() {
    let ran = run("/266", &fixture::reply(266), false, |_| {});
    assert_eq!(ran.result, Ok(()));
    let abc = [&[b'a'; 64][..], &[b'b'; 48], &[b'c'; 32], b"\n"].concat();
    assert_eq!(ran.seen.body(), abc);
    assert_eq!(
        ran.seen.of("trailer"),
        [b"chunky-trailer: header data\r\n".to_vec()]
    );
    let ran = run("/326", &fixture::reply(326), false, |o| o.http.raw = true);
    assert_eq!(ran.result, Ok(()));
    assert_eq!(
        ran.seen.body(),
        b"18\r\nline 1\n line 2\n  line 3\n\r\n0\r\n\r\n"
    );
}

/// A HEAD asks for no body, and one that comes anyway gives up the
/// connection.
#[test]
fn a_head_wants_no_body() {
    let reply = b"HTTP/1.1 200 OK\r\nContent-Length: 6\r\n\r\n";
    let ran = run("/", reply, false, |o| {
        o.method = crate::options::Method::Head
    });
    assert_eq!((ran.result, ran.seen.body()), (Ok(()), Vec::new()));
    assert!(ran.request.starts_with(b"HEAD / HTTP/1.1\r\n"));
    assert!(ran.seen.text().last().unwrap().ends_with("left intact\n"));
    let reply = b"HTTP/1.1 200 OK\r\nContent-Length: 6\r\n\r\nabcdef";
    let ran = run("/", reply, false, |o| {
        o.method = crate::options::Method::Head
    });
    assert_eq!((ran.result, ran.seen.body()), (Ok(()), Vec::new()));
    assert_eq!(
        ran.seen.text().last().unwrap(),
        "shutting down connection #0\n"
    );
}

/// A bad head fails the transfer with C's words.
#[test]
fn a_bad_head_fails() {
    let ran = run("/", b"HTTP/1.1 200 OK\r\nno colon\r\n\r\n", true, |_| {});
    assert_eq!(ran.result, Err(ErrorKind::WeirdServerReply));
    assert!(
        ran.seen
            .text()
            .contains(&"Header without colon\n".to_string())
    );
    assert_eq!(ran.seen.text().last().unwrap(), "closing connection #0\n");
    let ran = run("/", b"hello\r\n", true, |_| {});
    assert_eq!(ran.result, Err(ErrorKind::UnsupportedProtocol));
    assert!(
        ran.seen
            .text()
            .contains(&"Received HTTP/0.9 when not allowed\n".to_string())
    );
    let ran = run("/", b"hello\r\nworld", true, |o| o.http.allow_09 = true);
    assert_eq!(
        (ran.result, ran.seen.body()),
        (Ok(()), b"hello\r\nworld".to_vec())
    );
}

/// A HEAD answered in HTTP/0.9 has no head to make the body fine: what
/// was taken for a status line goes unwritten, and a body past it fails
/// the transfer (`Curl_http_write_resp_hds`, `cw_download_write`).
#[test]
fn a_head_answered_in_http_0_9_is_refused() {
    let head = |reply: &[u8]| {
        let ran = run("/", reply, true, |o| {
            o.http.allow_09 = true;
            o.method = Method::Head;
        });
        (ran.result, ran.seen.body())
    };
    assert_eq!(head(b"hello\n"), (Err(ErrorKind::GotNothing), vec![]));
    assert_eq!(head(b"hel"), (Err(ErrorKind::GotNothing), vec![]));
    assert_eq!(
        head(b"hello\nworld\n"),
        (Err(ErrorKind::WeirdServerReply), vec![])
    );
}

/// With failing on errors asked for, a code of 400 or more fails the
/// transfer at the end of its head: the reason is traced before the blank
/// line, which is still delivered, the body is not, and the connection
/// closes (C's `http_on_response`, checked against the C binary).
#[test]
fn a_failing_code_ends_the_transfer_at_its_head() {
    let reply = b"HTTP/1.1 404 Not Found\r\nContent-Length: 5\r\nA: b\r\n\r\nabcde";
    let ran = run("/", reply, false, |o| o.http.fail_on_error = true);
    assert_eq!(ran.result, Err(ErrorKind::HttpReturnedError));
    assert_eq!(ran.seen.body(), b"");
    assert_eq!(ran.seen.of("header").last().unwrap(), b"\r\n");
    let lines: Vec<(&str, Vec<u8>)> = ran
        .seen
        .0
        .borrow()
        .iter()
        .filter(|(w, _)| matches!(*w, "text" | "in"))
        .cloned()
        .collect();
    let failed = lines
        .iter()
        .position(|(_, l)| l == b"The requested URL returned error: 404\n")
        .expect("the reason");
    assert_eq!(lines[failed + 1], ("in", b"\r\n".to_vec()));
    assert_eq!(ran.seen.text().last().unwrap(), "closing connection #0\n");
    // Below 400, or without asking, nothing fails.
    for (reply, fail) in [
        (&b"HTTP/1.1 399 X\r\nContent-Length: 0\r\n\r\n"[..], true),
        (b"HTTP/1.1 500 X\r\nContent-Length: 0\r\n\r\n", false),
    ] {
        let ran = run("/", reply, false, |o| o.http.fail_on_error = fail);
        assert_eq!(ran.result, Ok(()));
    }
    // A HEAD fails too.
    let ran = run("/", b"HTTP/1.1 401 X\r\n\r\n", false, |o| {
        o.http.fail_on_error = true;
        o.method = Method::Head;
    });
    assert_eq!(ran.result, Err(ErrorKind::HttpReturnedError));
}

/// What the end of a final head fails on is said before its blank line
/// is traced, the line still delivered; a code below 100 is said after
/// (`http_on_response`, checked against the C binary).
#[test]
fn a_head_s_end_fails_around_its_blank_line() {
    let order = |reply: &[u8], set: fn(&mut Options)| {
        let ran = run("/", reply, false, set);
        assert_eq!(ran.seen.of("header").last().unwrap(), b"\r\n");
        let seen = ran.seen.0.borrow();
        let blank = seen.iter().position(|(w, l)| *w == "in" && l == b"\r\n");
        let said = seen.iter().position(|(w, l)| {
            *w == "text"
                && matches!(
                    &l[..],
                    b"Maximum file size exceeded\n"
                        | b"Unsupported response code in HTTP response\n"
                )
        });
        (ran.result, said < blank)
    };
    assert_eq!(
        order(b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\nabc", |o| {
            o.limits.max_filesize = std::num::NonZeroU64::new(10);
        }),
        (Err(ErrorKind::FilesizeExceeded), true)
    );
    assert_eq!(
        order(b"HTTP/1.1 099 X\r\nA: b\r\n\r\nabc", |_| {}),
        (Err(ErrorKind::UnsupportedProtocol), false)
    );
}

/// A body of a known size is read no further than its end: what follows
/// it in a later read stays unread, and the connection is kept
/// (`xfer_recv_resp`).
#[test]
fn a_body_is_read_no_further_than_its_size() {
    let mut reply = b"HTTP/1.1 200 OK\r\nContent-Length: 20000\r\n\r\n".to_vec();
    reply.resize(reply.len() + 20000, b'x');
    reply.extend_from_slice(b"EXTRA");
    let ran = run("/", &reply, false, |_| {});
    assert_eq!((ran.result, ran.seen.body().len()), (Ok(()), 20000));
    let reads: Vec<usize> = ran.seen.of("data").iter().map(Vec::len).collect();
    // The head is 42 bytes of the first read.
    assert_eq!(reads, [16384 - 42, 20000 - (16384 - 42)]);
    assert!(ran.seen.text().last().unwrap().ends_with("left intact\n"));
}

/// A second request goes over the connection the first left intact, which
/// a reply that is no HTTP then cannot be HTTP/0.9 on (`Invalid status
/// line`).
#[test]
fn a_kept_connection_carries_the_next_request() {
    let first = b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nabc";
    let (mut m, talk, _clock) = server(&[first, first], false);
    let one = get(&mut m, "/1", talk.clone(), |_| {});
    let two = get(&mut m, "/2", talk.clone(), |_| {});
    assert_eq!((one.result, two.result), (Ok(()), Ok(())));
    assert_eq!(two.seen.body(), b"abc");
    assert_eq!(
        talk.received(),
        [request_of("/1"), request_of("/2")].concat()
    );
    assert_eq!(
        two.seen.text()[0],
        "Reusing existing http: connection with host 127.0.0.1\n"
    );
    let (mut m, talk, _clock) = server(&[first, b"hello\r\n"], false);
    get(&mut m, "/1", talk.clone(), |_| {}).result.unwrap();
    let two = get(&mut m, "/2", talk, |o| o.http.allow_09 = true);
    assert_eq!(two.result, Err(ErrorKind::WeirdServerReply));
    assert!(
        two.seen
            .text()
            .contains(&"Invalid status line\n".to_string())
    );
}

/// A head cut short by the close, with its size known, ends as the C
/// tool ends it: short by the whole body, unless it is empty or no body
/// was asked for.
#[test]
fn a_head_cut_short_misses_its_body() {
    let reply = |size: u32| format!("HTTP/1.1 200 OK\r\nContent-Length: {size}\r\nX: y\r\n");
    let ran = run("/", reply(5).as_bytes(), true, |_| {});
    assert_eq!(ran.result, Err(ErrorKind::PartialFile));
    assert!(
        ran.seen
            .text()
            .iter()
            .any(|l| l == "transfer closed with 5 bytes remaining to read\n")
    );
    assert_eq!(run("/", reply(0).as_bytes(), true, |_| {}).result, Ok(()));
    let head = run("/", reply(5).as_bytes(), true, |o| o.method = Method::Head);
    assert_eq!(head.result, Ok(()));
}

/// The header size counts every head line and trailer received, an
/// interim response's with them, as C's (`CURLINFO_HEADER_SIZE`): the C
/// tool's `-w %{size_header}` says 92 for this reply.
#[test]
fn the_header_size_counts_interim_heads_and_trailers() {
    let ran = run(
        "/",
        b"HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nTrailer: X\r\n\r\n2\r\nok\r\n0\r\nX: yes\r\n\r\n",
        false,
        |_| {},
    );
    assert_eq!(ran.result, Ok(()));
    assert_eq!(ran.easy.report().sizes().header(), 92);
}

/// Bytes after the last chunk are left over, and said so; none, nothing
/// is said. The body is traced as it came, chunk lines and leftovers
/// with it, before decoding (`cw_raw_write`, as the C tool's `-v` shows
/// it).
#[test]
fn bytes_after_the_chunks_are_left_over() {
    let chunked = "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nok\r\n0\r\n\r\n";
    let ran = run("/", format!("{chunked}extra").as_bytes(), false, |_| {});
    assert_eq!((ran.result, ran.seen.body()), (Ok(()), b"ok".to_vec()));
    assert_eq!(ran.seen.of("data").concat(), b"2\r\nok\r\n0\r\n\r\nextra");
    let leftovers = |ran: &Ran| {
        ran.seen
            .text()
            .into_iter()
            .filter(|l| l.starts_with("Leftovers"))
            .collect::<Vec<_>>()
    };
    assert_eq!(leftovers(&ran), ["Leftovers after chunking: 5 bytes\n"]);
    let ran = run("/", chunked.as_bytes(), false, |_| {});
    assert_eq!(leftovers(&ran), Vec::<String>::new());
}

/// Counts its calls, aborting at the one numbered `abort_at`.
#[derive(Clone, Default)]
struct AbortsAt {
    calls: Rc<std::cell::Cell<u32>>,
    abort_at: u32,
}

impl crate::handler::ProgressHandler for AbortsAt {
    fn progress(
        &self,
        _: &mut TransferCx<'_>,
        _: crate::handler::ProgressNow,
    ) -> crate::handler::ProgressVerdict {
        let n = self.calls.get() + 1;
        self.calls.set(n);
        if n == self.abort_at {
            crate::handler::ProgressVerdict::Abort
        } else {
            crate::handler::ProgressVerdict::Continue
        }
    }
}

/// A progress handler that aborts at the last pass, once the request is
/// done, fails the transfer and closes its connection, as the C library
/// does (checked with a program on the C build: the next transfer
/// connects anew).
#[test]
fn an_abort_at_the_last_progress_pass_closes_the_connection() {
    let reply = b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nabc";
    let (mut m, talk, _clock) = server(&[reply, reply], false);
    let counting = AbortsAt::default();
    let progress = |h: &AbortsAt| {
        let h = h.clone();
        move |o: &mut Options| {
            o.progress = crate::options::Progress::Handler(Handler::progress(h).unwrap());
        }
    };
    let one = get(&mut m, "/1", talk.clone(), progress(&counting));
    assert_eq!(one.result, Ok(()));
    assert!(one.seen.text().last().unwrap().ends_with("left intact\n"));
    let last = AbortsAt {
        calls: Rc::default(),
        abort_at: counting.calls.get(),
    };
    let two = get(&mut m, "/2", talk, progress(&last));
    assert_eq!(two.result, Err(ErrorKind::AbortedByCallback));
    assert_eq!(
        last.calls.get(),
        counting.calls.get(),
        "aborted at the last"
    );
    let text = two.seen.text();
    assert!(
        text.iter().any(|l| l == "closing connection #0\n"),
        "{text:?}"
    );
}

/// While its response is to come, a request waits to read its socket;
/// paused, it waits on nothing (`Curl_http_perform_pollset`).
#[test]
fn an_exchange_waits_to_read_its_socket() {
    use crate::conn::io::Events;
    use crate::deliver::PauseRequest;
    let (mut m, _talk, _clock) = server(&[], false);
    let mut e = Easy::new();
    let url = format!("http://127.0.0.1:{PORT}/");
    e.options_mut().set_url(Some(url.as_bytes())).unwrap();
    let id = m.add(e, (), &mut NoEvents).unwrap();
    m.perform(&mut NoEvents).unwrap();
    let waits = |m: &Multi| {
        let mut seen = Vec::new();
        m.sockets(|_, events| seen.push(events));
        seen
    };
    assert_eq!(waits(&m), [Events::IN]);
    m.pause(id, PauseRequest::RECV, &mut NoEvents).unwrap();
    assert_eq!(waits(&m), []);
}

/// A resumed GET asks for the rest with `Range`, and takes a response that
/// starts where it asked, or the whole document when the server says so
/// (`Content-Range: */total`) or the stored part is all of it; anything
/// else fails at the head (`http_firstwrite`, checked against the C
/// binary).
#[test]
fn a_resumed_get_takes_only_the_rest() {
    let resume = |o: &mut Options| o.resume = Some(Resume::At(NonZeroU64::new(18).unwrap()));
    let ran = run(
        "/",
        b"HTTP/1.1 206 P\r\nContent-Range: bytes 18-21/22\r\nContent-Length: 4\r\n\r\nabc\n",
        false,
        resume,
    );
    assert_eq!(ran.result, Ok(()));
    assert_eq!(
        ran.request,
        format!(
            "GET / HTTP/1.1\r\nHost: 127.0.0.1:{PORT}\r\nRange: bytes=18-\r\n\
             User-Agent: curl/test\r\nAccept: */*\r\n\r\n"
        )
        .as_bytes()
    );
    assert_eq!(ran.seen.body(), b"abc\n");
    // The application's own Range replaces it.
    let ran = run(
        "/",
        b"HTTP/1.1 206 P\r\nContent-Range: bytes 18-\r\n\r\n",
        true,
        |o| {
            resume(o);
            o.http.headers = UserHeaders::new([&b"Range: bytes=1-"[..]]).unwrap();
        },
    );
    assert!(
        String::from_utf8(ran.request)
            .unwrap()
            .contains("\r\nRange: bytes=1-\r\n")
    );
    let cannot = "HTTP server does not seem to support byte ranges. Cannot resume.\n";
    for reply in [
        &b"HTTP/1.1 206 P\r\nContent-Range: bytes 5-8/22\r\nContent-Length: 4\r\n\r\nabc\n"[..],
        b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nabc\n",
        b"HTTP/1.0 200 OK\r\n\r\nall of it\n",
        // No start is the whole document only on a success.
        b"HTTP/1.1 300 X\r\nContent-Range: bytes */100\r\nContent-Length: 3\r\n\r\nabc",
    ] {
        let ran = run("/", reply, true, resume);
        assert_eq!(ran.result, Err(ErrorKind::RangeError));
        assert_eq!(ran.seen.body(), b"");
        assert!(ran.seen.text().iter().any(|l| l == cannot));
    }
    let ran = run(
        "/",
        b"HTTP/1.1 200 OK\r\nContent-Range: */22\r\nContent-Length: 4\r\n\r\nall\n",
        false,
        resume,
    );
    assert_eq!((ran.result, ran.seen.body()), (Ok(()), b"all\n".to_vec()));
    let ran = run(
        "/",
        b"HTTP/1.1 299 X\r\nContent-Range: bytes */100\r\nContent-Length: 3\r\n\r\nabc",
        false,
        resume,
    );
    assert_eq!((ran.result, ran.seen.body()), (Ok(()), b"abc".to_vec()));
    let ran = run(
        "/",
        b"HTTP/1.1 200 OK\r\nContent-Length: 18\r\n\r\n",
        false,
        resume,
    );
    assert_eq!((ran.result, ran.seen.body()), (Ok(()), Vec::new()));
    assert!(
        ran.seen
            .text()
            .iter()
            .any(|l| l == "The entire document is already downloaded\n")
    );
}

/// A 416 to a resumed GET is the file being whole already: its body is
/// read and dropped, neither written nor traced, and the connection kept
/// (`ignorebody`, checked against the C binary).
#[test]
fn a_416_to_a_resumed_get_is_read_and_dropped() {
    let ran = run(
        "/",
        b"HTTP/1.1 416 No\r\nContent-Length: 4\r\n\r\nnope",
        false,
        |o| {
            o.resume = Some(Resume::At(NonZeroU64::new(18).unwrap()));
            o.http.fail_on_error = true;
        },
    );
    assert_eq!(ran.result, Ok(()));
    assert_eq!(ran.seen.body(), b"");
    assert!(ran.seen.of("data").is_empty());
    let text = ran.seen.text();
    assert!(text.iter().any(|l| l == "setting size while ignoring\n"));
    assert!(text.last().unwrap().ends_with("left intact\n"));
    assert_eq!(ran.easy.report().sizes().download(), 4);
}

/// What a header handler sees of the report at each line: the code and
/// version once the status line is read, the body's size by the blank
/// line (`http_size` runs before the last header is written, as test
/// 1485 reads it).
#[derive(Clone, Default)]
struct Watched(Rc<RefCell<Vec<WatchedLine>>>);

/// A header line, with the response code and body size known then.
type WatchedLine = (Vec<u8>, Option<u16>, Option<u64>);

impl HeaderHandler for Watched {
    fn header(&self, cx: &mut TransferCx<'_>, line: &[u8], _: HeaderOrigin) -> Write {
        let r = cx.info(cx.me()).unwrap();
        let seen = (
            line.to_vec(),
            r.response_code(),
            r.sizes().download_expected(),
        );
        self.0.borrow_mut().push(seen);
        Write::Accepted
    }
}

#[test]
fn the_report_knows_the_response_as_its_lines_arrive() {
    let watched = Watched::default();
    let w = watched.clone();
    let ran = run(
        "/",
        b"HTTP/1.1 100 Go\r\n\r\nHTTP/1.0 200 OK\r\nRetry-After: 99999\r\nContent-Length: 3\r\n\r\nabc",
        true,
        move |o| o.callbacks.header = Some(Handler::header(w).unwrap()),
    );
    assert_eq!(ran.result, Ok(()));
    let seen = watched.0.borrow();
    let at = |i: usize| (seen[i].1, seen[i].2);
    assert_eq!(seen[0].0, b"HTTP/1.1 100 Go\r\n");
    assert_eq!(at(0), (Some(100), None));
    assert_eq!(at(2), (Some(200), None));
    assert_eq!(at(4), (Some(200), None));
    assert_eq!(seen[5].0, b"\r\n");
    assert_eq!(at(5), (Some(200), Some(3)));
    let r = ran.easy.report();
    assert_eq!(r.response_version(), Some(ResponseVersion::Http10));
    // At most six hours.
    assert_eq!(r.retry_after(), Some(Duration::from_secs(21600)));
}

/// `Retry-After` in seconds or as a date; what is neither, or a date
/// passed, is 0 (`http_header_r`).
#[test]
fn retry_after_reads_seconds_and_dates() {
    // Sun, 06 Nov 1994 08:49:37 GMT
    let now = 784_111_777;
    let after = |line: &[u8]| framing::retry_after(line, now).map(|d| d.as_secs());
    assert_eq!(after(b"Retry-After: 22\r\n"), Some(22));
    assert_eq!(after(b"retry-after:\t 7x\r\n"), Some(7));
    assert_eq!(after(b"Retry-After: soon\r\n"), Some(0));
    assert_eq!(after(b"Retry-After: 99999999999999999999\r\n"), Some(0));
    assert_eq!(after(b"Retry-After: 21601\r\n"), Some(21600));
    assert_eq!(after(b"Retry-Afte: 1\r\n"), None);
    assert_eq!(
        after(b"Retry-After: Sun, 06 Nov 1994 08:50:07 GMT\r\n"),
        Some(30)
    );
    assert_eq!(
        after(b"Retry-After: Sun, 06 Nov 1994 08:49:37 GMT\r\n"),
        Some(0)
    );
    assert_eq!(
        after(b"Retry-After: Sun, 06 Nov 1994 08:49:36 GMT\r\n"),
        Some(0)
    );
    assert_eq!(
        after(b"Retry-After: Wed, 31 Dec 2138 02:26:59 GMT\r\n"),
        Some(21600)
    );
    // A number starting a date is read as the date: passed, not 1.
    assert_eq!(after(b"Retry-After: 01 Nov 1994\r\n"), Some(0));
}

/// A `Retry-After` date is counted from the multi's calendar time.
#[test]
fn a_retry_after_date_counts_from_the_clock() {
    let reply = b"HTTP/1.1 503 Busy\r\nRetry-After: Sun, 06 Nov 1994 08:50:07 GMT\r\nContent-Length: 0\r\n\r\n";
    let (mut m, talk, clock) = server(&[reply], false);
    clock.advance(Duration::from_secs(5));
    clock.set_unix_time(784_111_777);
    clock.advance(Duration::from_secs(10));
    assert_eq!(clock.unix_time(), 784_111_787);
    let ran = get(&mut m, "/", talk, |_| {});
    assert_eq!(ran.result, Ok(()));
    assert_eq!(
        ran.easy.report().retry_after(),
        Some(Duration::from_secs(20))
    );
    // None asked, none is reported.
    let ran = run(
        "/",
        b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n",
        false,
        |_| {},
    );
    assert_eq!(ran.easy.report().retry_after(), None);
}

/// The report's URL and the request keep an empty query, as C's do
/// (`CURLU_GET_EMPTY`).
#[test]
fn the_report_s_url_and_the_request_keep_an_empty_query() {
    let ran = run(
        "/x?",
        b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n",
        false,
        |_| {},
    );
    assert_eq!(ran.result, Ok(()));
    assert_eq!(
        ran.easy.report().url().unwrap(),
        format!("http://127.0.0.1:{PORT}/x?").as_bytes()
    );
    assert_eq!(ran.request, request_of("/x?"));
}

/// The report keeps the URL the transfer used, without its credentials.
#[test]
fn the_report_s_url_has_no_credentials() {
    let ran = run(
        "/",
        b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n",
        false,
        |o| {
            let url = format!("http://u:secret@127.0.0.1:{PORT}/x?q");
            o.set_url(Some(url.as_bytes())).unwrap();
        },
    );
    assert_eq!(ran.result, Ok(()));
    assert!(
        ran.seen
            .text()
            .iter()
            .any(|l| l == "Server auth using Basic with user 'u'\n"),
        "{:?}",
        ran.seen.text()
    );
    assert_eq!(
        ran.easy.report().url().unwrap(),
        format!("http://127.0.0.1:{PORT}/x?q").as_bytes()
    );
}

/// A reply each test server below gives.
const OK: &[u8] = b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nok\n";

/// A multi whose server at `PORT`, `peer`, takes the connections
/// `conversations` in turn.
fn serving(peer: Peer, conversations: &[&Conversation]) -> Multi {
    let clock = ManualClock::new().unwrap();
    let at = SocketAddr::from(([127, 0, 0, 1], PORT));
    let mut net = FakeNet::new(clock.clone()).with_peer(at, peer);
    for c in conversations {
        net = net.with_conversation(at, (*c).clone());
    }
    let env = Env {
        clock: Box::new(clock),
        net: Box::new(net),
        arena: ArenaPolicy::new(16, 0).unwrap(),
        waker: None,
    };
    Multi::new(env).unwrap()
}

/// A connection the server answers once, then closes as it is reused.
fn answers_once() -> Conversation {
    Conversation::new(OK, false).hanging_up_unanswered()
}

/// A request over a reused connection that closed as it was reused, with
/// nothing back, is made again on a fresh connection, credentials and
/// all (`Curl_retry_request`); its headers are the next request's. The
/// C build traces the same lines for the same exchange.
#[test]
fn a_request_over_a_reused_connection_that_died_is_made_again() {
    let first = answers_once();
    let fresh = Conversation::new(OK, false);
    let mut m = serving(Peer::Accepts, &[&first, &fresh]);
    assert_eq!(get(&mut m, "/a", first.clone(), |_| {}).result, Ok(()));
    let url = format!("http://u:p@127.0.0.1:{PORT}/b");
    let ran = get(&mut m, "/b", fresh.clone(), |o| {
        o.set_url(Some(url.as_bytes())).unwrap();
    });
    assert_eq!(ran.result, Ok(()));
    assert_eq!(ran.seen.body(), b"ok\n");
    let authed = request_of("/b").len() - 2;
    let second = &fresh.received();
    assert!(
        second.starts_with(b"GET /b HTTP/1.1\r\n")
            && fixture::find(second, b"Authorization: Basic dTpw\r\n").is_some()
            && second.len() > authed,
        "{}",
        String::from_utf8_lossy(second)
    );
    let text = ran.seen.text();
    let start = text
        .iter()
        .position(|l| l.starts_with("Reusing existing"))
        .unwrap();
    assert_eq!(
        text[start + 2..start + 6],
        [
            "Request completely sent off\n".to_string(),
            "Connection died, retrying a fresh connect (retry count: 1)\n".to_string(),
            "shutting down connection #0\n".to_string(),
            format!("Issue another request to this URL: 'http://u:p@127.0.0.1:{PORT}/b'\n"),
        ]
    );
    assert_eq!(
        text[start + 6..start + 8],
        [
            "Hostname 127.0.0.1 was found in DNS cache\n".to_string(),
            format!("  Trying 127.0.0.1:{PORT}...\n"),
        ]
    );
    assert_eq!(
        text.last().unwrap(),
        &format!("Connection #1 to host 127.0.0.1:{PORT} left intact\n")
    );
    let report = ran.easy.report();
    assert_eq!(report.failure(), None, "{text:?}");
    let headers = report.headers();
    let any = crate::report::Origins::ALL;
    use crate::report::{HeaderError, Request};
    assert_eq!(
        headers
            .get(b"Content-Length", 0, any, Request::Nth(0))
            .err(),
        Some(HeaderError::Missing)
    );
    assert!(
        headers
            .get(b"Content-Length", 0, any, Request::Nth(1))
            .is_ok()
    );
}

/// A fresh connection that closes with nothing back is not tried again:
/// the reply is empty.
#[test]
fn a_fresh_connection_that_died_is_an_empty_reply() {
    let dead = Conversation::replies(&[], false).hanging_up_unanswered();
    let mut m = serving(Peer::Accepts, &[&dead]);
    let ran = get(&mut m, "/", dead.clone(), |_| {});
    assert_eq!(ran.result, Err(ErrorKind::GotNothing));
    assert!(!ran.seen.text().iter().any(|l| l.contains("retrying")));
}

/// A request is made again on fresh connections at most five times: six
/// idle connections that each die as they are reused fail the transfer.
/// Each retry takes another idle connection, as C's would.
#[test]
fn a_request_is_retried_five_times_at_most() {
    let dying: Vec<Conversation> = (0..6).map(|_| answers_once()).collect();
    // Accepting late, so that six transfers at once open six connections.
    let late = Peer::AcceptsAfter(Duration::from_millis(5));
    let mut m = serving(late, &dying.iter().collect::<Vec<_>>());
    let mut ids = Vec::new();
    for _ in 0..6 {
        let mut e = Easy::new();
        let url = format!("http://127.0.0.1:{PORT}/");
        e.options_mut().set_url(Some(url.as_bytes())).unwrap();
        e.options_mut().callbacks.write = Some(Handler::write(Seen::default()).unwrap());
        ids.push(m.add(e, (), &mut NoEvents).unwrap());
    }
    // Kept in the multi, so that the pool keeps their connections.
    for &id in &ids {
        let done = drive_to_completion(&mut m, id, &mut NoEvents).unwrap();
        assert_eq!(done, Ok(()));
    }
    let ran = get(&mut m, "/", dying[0].clone(), |_| {});
    let text = ran.seen.text();
    assert_eq!(ran.result, Err(ErrorKind::SendError), "{text:#?}");
    let retries = text
        .iter()
        .filter(|l| l.starts_with("Connection died, retrying"))
        .count();
    assert_eq!(retries, 5, "{text:?}");
    assert_eq!(
        ran.easy.report().failure(),
        Some(&b"Connection died, tried 5 times before giving up"[..])
    );
}

/// A reused connection that closes once a response has begun is not
/// tried again: what came is all there is.
#[test]
fn a_get_with_a_reused_connection_that_closes_mid_body_fails() {
    let cut = b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nab";
    let talk = Conversation::replies(&[OK, cut], true);
    let mut m = serving(Peer::Accepts, &[&talk]);
    assert_eq!(get(&mut m, "/a", talk.clone(), |_| {}).result, Ok(()));
    let ran = get(&mut m, "/b", talk.clone(), |_| {});
    assert_eq!(ran.result, Err(ErrorKind::PartialFile));
    assert!(!ran.seen.text().iter().any(|l| l.contains("retrying")));
}

/// A response read until the connection closes, over a reused one, ends
/// the request: it got something back, so it is not tried again.
#[test]
fn a_response_until_close_over_a_reused_connection_is_whole() {
    let until_close = b"HTTP/1.1 200 OK\r\n\r\nab";
    let talk = Conversation::replies(&[OK, until_close], true);
    let mut m = serving(Peer::Accepts, &[&talk]);
    assert_eq!(get(&mut m, "/a", talk.clone(), |_| {}).result, Ok(()));
    let ran = get(&mut m, "/b", talk.clone(), |_| {});
    assert_eq!((ran.result, ran.seen.body()), (Ok(()), b"ab".to_vec()));
    assert!(!ran.seen.text().iter().any(|l| l.contains("retrying")));
}

/// A request with `body` sent by `method`, its head before it.
fn with_body(method: Method, body: &[u8], set: impl FnOnce(&mut Options)) -> Ran {
    let body = body.to_vec();
    run(
        "/p",
        b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n",
        false,
        |o| {
            o.method = method;
            o.upload =
                crate::options::UploadSource::Bytes(curl_alloc::TryRc::try_new(body).unwrap());
            set(o);
        },
    )
}

/// A POST sends its body behind its head, sized, typed as a form; the
/// trace has the head and the body apart, and the request's size both.
#[test]
fn a_post_sends_its_body_after_its_head() {
    let ran = with_body(Method::Post, b"a=b", |_| {});
    assert_eq!(ran.result, Ok(()));
    let head = format!(
        "POST /p HTTP/1.1\r\nHost: 127.0.0.1:{PORT}\r\nUser-Agent: curl/test\r\nAccept: */*\r\n\
         Content-Length: 3\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\n"
    );
    assert_eq!(ran.request, [head.as_bytes(), b"a=b"].concat());
    assert_eq!(ran.seen.of("out"), [head.as_bytes()]);
    assert_eq!(ran.seen.of("dataout"), [b"a=b"]);
    let sizes = *ran.easy.report().sizes();
    assert_eq!(
        (sizes.upload(), sizes.request()),
        (3, ran.request.len() as u64)
    );
    assert!(
        ran.seen
            .text()
            .contains(&"upload completely sent off: 3 bytes\n".to_string())
    );
}

/// A PUT is not typed; an empty body is announced as such.
#[test]
fn a_put_is_sized_and_an_empty_body_announced() {
    let ran = with_body(Method::Upload, b"xyz", |_| {});
    assert_eq!(ran.result, Ok(()));
    assert!(ran.request.starts_with(b"PUT /p HTTP/1.1\r\n"));
    assert!(ran.request.ends_with(b"\r\nContent-Length: 3\r\n\r\nxyz"));
    let ran = with_body(Method::Post, b"", |_| {});
    assert!(ran.request.ends_with(
        b"Content-Length: 0\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\n"
    ));
    assert!(
        ran.seen
            .text()
            .contains(&"Request completely sent off\n".to_string())
    );
}

/// The application's Content-Length and Content-Type replace the
/// library's, an empty one dropping it.
#[test]
fn the_application_s_content_headers_replace_the_library_s() {
    let ran = with_body(Method::Post, b"a=b", |o| {
        o.http.headers =
            UserHeaders::new([&b"Content-Type: text/plain"[..], b"Content-Length:"]).unwrap();
    });
    let request = String::from_utf8(ran.request).unwrap();
    assert!(!request.contains("Content-Length"), "{request}");
    assert!(
        request.contains("\r\nContent-Type: text/plain\r\n\r\na=b"),
        "{request}"
    );
    assert!(!request.contains("x-www-form-urlencoded"), "{request}");
}

/// A resumed upload is not HTTP's: refused before anything goes.
#[test]
fn a_resumed_body_is_refused() {
    let resumed = with_body(Method::Upload, b"a", |o| {
        o.resume = Some(Resume::At(NonZeroU64::new(1).unwrap()));
    });
    assert_eq!(resumed.result, Err(ErrorKind::BadFunctionArgument));
    assert!(resumed.request.is_empty());
}

/// A request sending `body`, answered with `reply`, and how long it
/// waited.
fn expecting(reply: &[u8], body: &[u8], set: impl FnOnce(&mut Options)) -> (Ran, Duration) {
    let (mut m, talk, clock) = server(&[reply], false);
    let start = clock.now();
    let body = body.to_vec();
    let ran = get(&mut m, "/p", talk, |o| {
        o.method = Method::Post;
        o.upload = crate::options::UploadSource::Bytes(curl_alloc::TryRc::try_new(body).unwrap());
        set(o);
    });
    let waited = clock.now().since(start);
    (ran, waited)
}

const OK_EMPTY: &[u8] = b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n";

/// A large body, or one asked so, is announced with `Expect:
/// 100-continue` and sent once the 100 comes, without waiting; one the
/// application says no `Expect` for is sent at once.
#[test]
fn a_body_waits_for_a_100() {
    let big = vec![b'x'; 1024 * 1024 + 1];
    let continued = [&b"HTTP/1.1 100 Continue\r\n\r\n"[..], OK_EMPTY].concat();
    let (ran, waited) = expecting(&continued, &big, |_| {});
    assert_eq!((ran.result, waited), (Ok(()), Duration::ZERO));
    let head_end = ran.request.len() - big.len();
    assert!(
        ran.request[..head_end].ends_with(
            b"Content-Type: application/x-www-form-urlencoded\r\nExpect: 100-continue\r\n\r\n"
        ),
        "{}",
        String::from_utf8_lossy(&ran.request[..head_end])
    );
    assert!(ran.request.ends_with(&big));
    assert!(
        !ran.seen
            .text()
            .iter()
            .any(|l| l.starts_with("Done waiting"))
    );
    let (asked, waited) = expecting(&continued, b"a=b", |o| {
        o.http.headers = UserHeaders::new([&b"Expect: 100-continue"[..]]).unwrap();
    });
    assert_eq!((asked.result, waited), (Ok(()), Duration::ZERO));
    let request = String::from_utf8(asked.request).unwrap();
    assert_eq!(request.matches("Expect").count(), 1, "{request}");
    assert!(request.ends_with("\r\n\r\na=b"), "{request}");
    let (unknown, waited) = expecting(&continued, b"", |o| o.upload = pieces(&[b"abc"]));
    assert_eq!((unknown.result, waited), (Ok(()), Duration::ZERO));
    let request = String::from_utf8(unknown.request).unwrap();
    assert!(
        request.contains("\r\nExpect: 100-continue\r\n\r\n3\r\nabc\r\n0\r\n\r\n"),
        "{request}"
    );
    let (not_asked, waited) = expecting(OK_EMPTY, &big, |o| {
        o.http.headers = UserHeaders::new([&b"Expect:"[..]]).unwrap();
    });
    assert_eq!((not_asked.result, waited), (Ok(()), Duration::ZERO));
    assert!(not_asked.request.ends_with(&big));
}

/// Without a 100, the body goes when the wait runs out, the response
/// already read.
#[test]
fn a_body_goes_when_the_wait_for_a_100_runs_out() {
    let (ran, waited) = expecting(OK_EMPTY, b"a=b", |o| {
        o.http.headers = UserHeaders::new([&b"Expect: 100-continue"[..]]).unwrap();
        o.http.continue_wait = crate::options::ContinueWait(Duration::from_millis(300));
    });
    assert_eq!((ran.result, waited), (Ok(()), Duration::from_millis(300)));
    assert!(ran.request.ends_with(b"\r\n\r\na=b"));
    let text = ran.seen.text();
    let done = text
        .iter()
        .position(|l| l == "Done waiting for 100-continue\n");
    let sent = text
        .iter()
        .position(|l| l == "upload completely sent off: 3 bytes\n");
    assert!(done.is_some() && done < sent, "{text:?}");
}

/// An error response before the body has gone stops it, the connection
/// not used again; the application can have it sent anyway.
#[test]
fn an_error_response_stops_the_body() {
    let not_found = b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n";
    let asked = |o: &mut Options| {
        o.http.headers = UserHeaders::new([&b"Expect: 100-continue"[..]]).unwrap();
    };
    let (ran, waited) = expecting(not_found, b"a=b", asked);
    assert_eq!((ran.result, waited), (Ok(()), Duration::ZERO));
    assert!(ran.request.ends_with(b"\r\n\r\n"), "the head alone");
    let text = ran.seen.text();
    for line in [
        "HTTP error before end of send, stop sending\n",
        "abort upload\n",
    ] {
        assert!(text.contains(&line.to_string()), "{text:?}");
    }
    assert!(
        text.iter()
            .any(|l| l.starts_with("shutting down connection")),
        "{text:?}"
    );
    let (kept, waited) = expecting(not_found, b"a=b", |o| {
        asked(o);
        o.http.keep_sending_on_error = true;
    });
    assert_eq!((kept.result, waited), (Ok(()), Duration::ZERO));
    assert!(kept.request.ends_with(b"\r\n\r\na=b"));
    assert!(
        kept.seen
            .text()
            .contains(&"HTTP error before end of send, keep sending\n".to_string())
    );
}

/// A body larger than the send buffer is read again as each buffer goes,
/// the first buffer shared with the head.
#[test]
fn a_body_larger_than_the_buffer_goes_in_buffers() {
    let body: Vec<u8> = (0..200_000u32).map(|i| (i % 251) as u8).collect();
    let ran = with_body(Method::Upload, &body, |_| {});
    assert_eq!(ran.result, Ok(()));
    assert!(ran.request.ends_with(&body));
    let head_len = ran.request.len() - body.len();
    let pieces = ran.seen.of("dataout");
    assert_eq!(pieces.concat(), body);
    assert_eq!(pieces[0].len(), 65536 - head_len, "behind the head");
    assert_eq!(pieces[1].len(), 65536);
    assert_eq!(ran.easy.report().sizes().upload(), body.len() as u64);
}

/// The application's method replaces the word on the request line; the
/// body is still the one the method implies.
#[test]
fn a_custom_method_is_sent_with_the_body_kept() {
    let ran = with_body(Method::Post, b"a=b", |o| {
        o.http.custom_method = Some(b"PATCH".to_vec());
    });
    assert_eq!(ran.result, Ok(()));
    assert!(ran.request.starts_with(b"PATCH /p HTTP/1.1\r\n"));
    assert!(ran.request.ends_with(b"x-www-form-urlencoded\r\n\r\na=b"));
}

/// A body read in these pieces, of unknown size.
fn pieces(pieces: &[&[u8]]) -> crate::options::UploadSource {
    struct Pieces(RefCell<Vec<Vec<u8>>>);
    impl crate::handler::ReadHandler for Pieces {
        fn read(&self, _: &mut TransferCx<'_>, buf: &mut [u8]) -> crate::handler::Read {
            let mut left = self.0.borrow_mut();
            if left.is_empty() {
                return crate::handler::Read::Eof;
            }
            let piece = left.remove(0);
            buf[..piece.len()].copy_from_slice(&piece);
            crate::handler::Read::Data(std::num::NonZeroUsize::new(piece.len()).unwrap())
        }
    }
    let left = pieces.iter().map(|p| p.to_vec()).collect();
    crate::options::UploadSource::Read {
        handler: Handler::read(Pieces(RefCell::new(left))).unwrap(),
        rewind: None,
        size: None,
    }
}

/// A body of unknown size goes chunked, each piece read a chunk; the
/// head says so and gives no length.
#[test]
fn a_body_of_unknown_size_goes_chunked() {
    let ran = with_body(Method::Post, b"", |o| {
        o.upload = pieces(&[b"abc", b"defgh"]);
        o.http.headers = UserHeaders::new([&b"Expect:"[..]]).unwrap();
    });
    assert_eq!(ran.result, Ok(()));
    let request = String::from_utf8(ran.request).unwrap();
    assert!(
        request.ends_with(
            "Accept: */*\r\nTransfer-Encoding: chunked\r\n\
             Content-Type: application/x-www-form-urlencoded\r\n\r\n\
             3\r\nabc\r\n5\r\ndefgh\r\n0\r\n\r\n"
        ),
        "{request}"
    );
    assert!(!request.contains("Content-Length"), "{request}");
    assert_eq!(ran.easy.report().sizes().upload(), 23, "framing counts");
}

/// HTTP/1.0 cannot send a body of unknown size.
#[test]
fn http_1_0_refuses_a_body_of_unknown_size() {
    let ran = with_body(Method::Upload, b"", |o| {
        o.upload = pieces(&[b"a"]);
        o.http.version = crate::options::HttpVersion::Http10;
    });
    assert_eq!(ran.result, Err(ErrorKind::UploadFailed));
    assert!(ran.request.is_empty());
    assert!(
        ran.seen
            .text()
            .contains(&"Chunky upload is not supported by HTTP 1.0\n".to_string())
    );
}

/// A body the application asks chunked is, sized or not, under its own
/// header; one that asks some other coding is sent as it is, unsized.
#[test]
fn the_application_s_transfer_encoding_decides() {
    let ran = with_body(Method::Upload, b"abc", |o| {
        o.http.headers = UserHeaders::new([&b"Transfer-Encoding: chunked"[..]]).unwrap();
    });
    assert_eq!(ran.result, Ok(()));
    let request = String::from_utf8(ran.request).unwrap();
    assert!(
        request.ends_with("Accept: */*\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n0\r\n\r\n"),
        "{request}"
    );
    assert_eq!(request.matches("Transfer-Encoding").count(), 1, "{request}");
    let ran = with_body(Method::Upload, b"", |o| {
        o.upload = pieces(&[b"abc"]);
        o.http.headers = UserHeaders::new([&b"Transfer-Encoding: gzip"[..], b"Expect:"]).unwrap();
    });
    assert_eq!(ran.result, Ok(()));
    let request = String::from_utf8(ran.request).unwrap();
    assert!(
        request.ends_with("Transfer-Encoding: gzip\r\n\r\nabc"),
        "{request}"
    );
    assert!(!request.contains("Content-Length"), "{request}");
}

/// A chunked body ends with the trailer handler's lines that read
/// `Name: value`, the others skipped; the handler can abort.
#[test]
fn a_chunked_body_ends_with_its_trailers() {
    struct Give(crate::handler::Trailers);
    impl crate::handler::TrailerHandler for Give {
        fn trailers(
            &self,
            _: &mut TransferCx<'_>,
            lines: &mut crate::handler::TrailerLines,
        ) -> crate::handler::Trailers {
            for line in [&b"X-A: 1"[..], b"bad", b"Y:z", b"Z: 2"] {
                lines.add(line).unwrap();
            }
            self.0
        }
    }
    let chunked = |verdict| {
        with_body(Method::Post, b"", move |o| {
            o.upload = pieces(&[b"abc"]);
            o.http.headers = UserHeaders::new([&b"Expect:"[..]]).unwrap();
            o.callbacks.trailer = Some(Handler::trailer(Give(verdict)).unwrap());
        })
    };
    let ran = chunked(crate::handler::Trailers::Done);
    assert_eq!(ran.result, Ok(()));
    assert!(
        ran.request
            .ends_with(b"\r\n\r\n3\r\nabc\r\n0\r\nX-A: 1\r\nZ: 2\r\n\r\n"),
        "{}",
        String::from_utf8_lossy(&ran.request)
    );
    let skipped = "Malformatted trailing header, skipping trailer\n".to_string();
    assert_eq!(ran.seen.text().iter().filter(|l| **l == skipped).count(), 2);
    let ran = chunked(crate::handler::Trailers::Abort);
    assert_eq!(ran.result, Err(ErrorKind::AbortedByCallback));
    assert!(
        ran.seen
            .text()
            .contains(&"operation aborted by trailing headers callback\n".to_string())
    );
}

/// A response's `Location:`, not followed, is kept resolved for the
/// application, whatever the status; an empty one or a repeat is
/// ignored, and a different second one fails before it is traced.
#[test]
fn a_location_not_followed_is_kept_resolved() {
    let reply = |headers: &str| {
        format!("HTTP/1.1 201 Created\r\n{headers}Content-Length: 0\r\n\r\n").into_bytes()
    };
    let ran = run(
        "/a/b",
        &reply("Location:\r\nLocation: c d?x\r\nLocation:  c d?x \r\n"),
        false,
        |_| {},
    );
    assert_eq!(ran.result, Ok(()));
    let shown = format!("http://127.0.0.1:{PORT}/a/c%20d?x");
    assert_eq!(ran.easy.report().redirect_url(), Some(shown.as_bytes()));

    let ran = run("/", &reply(""), false, |_| {});
    assert_eq!(ran.easy.report().redirect_url(), None);

    let ran = run(
        "/",
        &reply("Location: /one\r\nLocation: /two\r\n"),
        false,
        |_| {},
    );
    assert_eq!(ran.result, Err(ErrorKind::WeirdServerReply));
    let text = ran.seen.text();
    assert!(
        text.contains(&"Multiple Location headers\n".to_string()),
        "{text:?}"
    );
    let traced = ran.seen.of("in");
    assert!(
        traced.iter().any(|l| l.starts_with(b"Location: /one")),
        "the first is traced"
    );
    assert!(
        !traced.iter().any(|l| l.starts_with(b"Location: /two")),
        "the second is refused before it is traced"
    );
    assert_eq!(ran.easy.report().redirect_url(), None);
}

fn moved(location: &str, close: bool) -> Vec<u8> {
    let close = if close { "Connection: close\r\n" } else { "" };
    format!("HTTP/1.1 301 Moved\r\nLocation: {location}\r\n{close}Content-Length: 5\r\n\r\nmoved")
        .into_bytes()
}

/// A redirect followed: its body is dropped, the next request made on the
/// kept connection to where it leads, and counted.
#[test]
fn a_redirect_is_followed_on_the_kept_connection() {
    let first = moved("c?x", false);
    let (mut m, talk, _) = server(&[&first, OK], false);
    let ran = get(&mut m, "/a/b", talk, |o| o.http.follow = Follow::All);
    assert_eq!(ran.result, Ok(()));
    assert_eq!(ran.seen.body(), b"ok\n", "the redirect's body is dropped");
    let mut want = request_of("/a/b");
    want.extend_from_slice(&request_of("/a/c?x"));
    assert_eq!(
        String::from_utf8_lossy(&ran.request),
        String::from_utf8_lossy(&want)
    );
    let report = ran.easy.report();
    assert_eq!(report.redirects(), 1);
    assert_eq!(report.connects(), 1, "the connection is kept");
    assert_eq!(report.redirect_url(), None, "followed, not kept");
    let text = ran.seen.text();
    let ignoring = text
        .iter()
        .position(|l| l == "Ignoring the response-body\n");
    let issue = format!("Issue another request to this URL: 'http://127.0.0.1:{PORT}/a/c?x'\n");
    let issued = text.iter().position(|l| *l == issue);
    assert!(ignoring.is_some() && ignoring < issued, "{text:?}");
}

/// A redirect past the limit is not followed: where it would have led
/// is kept, and the transfer fails.
#[test]
fn redirects_stop_at_the_limit() {
    let first = moved("/b", false);
    let (mut m, talk, _) = server(&[&first, OK], false);
    let ran = get(&mut m, "/a", talk, |o| {
        o.http.follow = Follow::All;
        o.http.max_redirects = MaxRedirects(Some(0));
    });
    assert_eq!(ran.result, Err(ErrorKind::TooManyRedirects));
    assert_eq!(ran.request, request_of("/a"));
    let text = ran.seen.text();
    assert!(
        text.contains(&"Maximum (0) redirects followed\n".to_string()),
        "{text:?}"
    );
    let report = ran.easy.report();
    let shown = format!("http://127.0.0.1:{PORT}/b");
    assert_eq!(report.redirect_url(), Some(shown.as_bytes()));
    assert_eq!(report.redirects(), 0);
}

/// A redirect goes to no scheme but HTTP's and FTP's, whatever the
/// build knows.
#[test]
fn a_redirect_to_a_file_is_refused() {
    let ran = run("/a", &moved("file:///etc/passwd", false), false, |o| {
        o.http.follow = Follow::All;
    });
    assert_eq!(ran.result, Err(ErrorKind::UnsupportedProtocol));
    let text = ran.seen.text();
    assert!(
        text.contains(&"Protocol \"file\" is disabled (in redirect)\n".to_string()),
        "{text:?}"
    );
    assert_eq!(ran.seen.body(), b"");
}

/// The application's Authorization and Cookie go only to the origin the
/// transfer started at, unless it lets them go anywhere; its other
/// headers go everywhere.
#[test]
fn the_application_s_credentials_stay_with_the_first_origin() {
    for unrestricted in [false, true] {
        let location = format!("http://other.test:{PORT}/b");
        let first = Conversation::new(&moved(&location, true), true);
        // Moved again, on the other origin.
        let second = Conversation::replies(&[&moved("/c", false), OK], false);
        let mut m = serving(Peer::Accepts, &[&first, &second]);
        let entry = format!("other.test:{PORT}:127.0.0.1");
        let ran = get(&mut m, "/a", first.clone(), |o| {
            o.http.follow = Follow::All;
            o.http.unrestricted_auth = unrestricted;
            o.resolve.set([entry.as_bytes()]).unwrap();
            o.http.headers =
                UserHeaders::new([&b"Authorization: Basic eA=="[..], b"Cookie: a=b", b"X-A: 1"])
                    .unwrap();
        });
        assert_eq!(ran.result, Ok(()));
        assert_eq!(ran.seen.body(), b"ok\n");
        let sent = |r: &[u8], line: &[u8]| fixture::find(r, line).is_some();
        let first = first.received();
        assert!(sent(&first, b"Authorization: Basic eA==\r\n"));
        let second = second.received();
        let at = fixture::find(&second, b"GET /c ").expect("the second redirect is followed");
        for request in [&second[..at], &second[at..]] {
            assert!(sent(request, b"Host: other.test:8990\r\n"));
            assert!(sent(request, b"X-A: 1\r\n"));
            assert_eq!(
                sent(request, b"Authorization: Basic eA==\r\n"),
                unrestricted,
                "{}",
                String::from_utf8_lossy(request)
            );
            assert_eq!(sent(request, b"Cookie: a=b\r\n"), unrestricted);
        }
        assert_eq!(ran.easy.report().redirects(), 2);
    }
}

/// The application's login goes as Basic to the origin the transfer
/// started at, before the URL's own credentials; to another only if it
/// lets it, and a redirect's own credentials go there in its place.
#[test]
fn the_login_stays_with_the_first_origin() {
    let login = b"Authorization: Basic c21pdGg6ZG9nZ2ll\r\n";
    for (unrestricted, userinfo, second_has) in [
        (false, "", None),
        (true, "", Some(&login[..])),
        (false, "u:p@", Some(&b"Authorization: Basic dTpw\r\n"[..])),
    ] {
        let location = format!("http://{userinfo}other.test:{PORT}/b");
        let first = Conversation::new(&moved(&location, true), true);
        let second = Conversation::new(OK, false);
        let mut m = serving(Peer::Accepts, &[&first, &second]);
        let entry = format!("other.test:{PORT}:127.0.0.1");
        let url = format!("http://x:y@127.0.0.1:{PORT}/a");
        let ran = get(&mut m, "/a", first.clone(), |o| {
            o.set_url(Some(url.as_bytes())).unwrap();
            o.login = crate::options::Login::from_pair(b"smith:doggie").unwrap();
            o.http.follow = Follow::All;
            o.http.unrestricted_auth = unrestricted;
            o.resolve.set([entry.as_bytes()]).unwrap();
        });
        assert_eq!(ran.result, Ok(()));
        let has = |r: &[u8], line: &[u8]| fixture::find(r, line).is_some();
        assert!(has(&first.received(), login), "the login before the URL's");
        let second = second.received();
        let sent = fixture::find(&second, b"Authorization:").map(|at| {
            let end = at + fixture::find(&second[at..], b"\n").unwrap() + 1;
            &second[at..end]
        });
        assert_eq!(sent, second_has, "{location}, unrestricted {unrestricted}");
    }
}

const CHALLENGE: &[u8] = b"HTTP/1.1 401 Who\r\n\
    WWW-Authenticate: X-Other realm=\"a\", Basic realm=\"b\"\r\n\
    Content-Length: 5\r\n\r\nnope\n";

/// Wanting more than one method, a request goes without credentials; a
/// 401 offering one it can answer has it made again with them, counted
/// as a redirect, its body not delivered, and fail-on-error not failing
/// it. The report says what was offered and used.
#[test]
fn a_401_is_answered_with_a_method_it_offers() {
    for fail_on_error in [false, true] {
        let (mut m, talk, _) = server(&[CHALLENGE, OK], false);
        let ran = get(&mut m, "/a", talk.clone(), |o| {
            o.login = crate::options::Login::from_pair(b"u:p").unwrap();
            o.http.auth = crate::options::HttpAuth(AuthMethods::ANY);
            o.http.fail_on_error = fail_on_error;
        });
        assert_eq!(ran.result, Ok(()));
        let received = talk.received();
        let second = fixture::find(&received, b"GET /a")
            .map(|at| at + 1)
            .unwrap();
        let second = second + fixture::find(&received[second..], b"GET /a").unwrap();
        assert!(fixture::find(&received[..second], b"Authorization").is_none());
        assert!(fixture::find(&received[second..], b"Authorization: Basic dTpw\r\n").is_some());
        assert_eq!(ran.seen.body(), b"ok\n");
        let report = ran.easy.report();
        assert_eq!(report.redirects(), 1);
        assert_eq!(report.auth_offered(), AuthMethods::BASIC);
        assert_eq!(report.auth_used(), AuthMethods::BASIC);
        assert!(
            ran.seen
                .text()
                .contains(&"Ignoring the response-body\n".to_string())
        );
    }
}

/// The method a 401 chose is kept for the handle's next transfer, and
/// used at once, while it is among those wanted.
#[test]
fn the_method_chosen_is_kept_for_the_next_transfer() {
    let (mut m, talk, _) = server(&[CHALLENGE, OK], false);
    let ran = get(&mut m, "/a", talk, |o| {
        o.login = crate::options::Login::from_pair(b"u:p").unwrap();
        o.http.auth = crate::options::HttpAuth(AuthMethods::ANY);
    });
    assert_eq!(ran.result, Ok(()));
    let mut easy = ran.easy;
    for (want, sent) in [(AuthMethods::ANY, true), (AuthMethods::DIGEST, false)] {
        let (mut m, talk, _) = server(&[OK], false);
        easy.options_mut().http.auth = crate::options::HttpAuth(want);
        let id = m.add(easy, (), &mut NoEvents).unwrap();
        let result = drive_to_completion(&mut m, id, &mut NoEvents).unwrap();
        assert_eq!(result, Ok(()));
        easy = m.remove(id, &mut NoEvents).unwrap().easy;
        let received = talk.received();
        assert_eq!(
            fixture::find(&received, b"Authorization: Basic dTpw").is_some(),
            sent,
            "{want:?}"
        );
    }
}

const DIGEST_CHALLENGE: &[u8] = b"HTTP/1.1 401 Who\r\n\
    WWW-Authenticate: Digest realm=\"r\", nonce=\"n\"\r\nContent-Length: 0\r\n\r\n";

/// A POST with Digest wanted probes without its body, saying
/// `Content-Length: 0` in place of the application's own; the challenge
/// has it made again with the body and the answer (tests 175 and 1284).
#[test]
fn a_digest_post_probes_without_its_body() {
    let (mut m, talk, _) = server(&[DIGEST_CHALLENGE, OK], false);
    let ran = get(&mut m, "/a", talk, |o| {
        o.method = Method::Post;
        o.upload = UploadSource::Bytes(curl_alloc::TryRc::try_new(b"a=b".to_vec()).unwrap());
        o.http.headers = UserHeaders::new([&b"Content-Length: 3"[..]]).unwrap();
        o.login = crate::options::Login::from_pair(b"u:p").unwrap();
        o.http.auth = crate::options::HttpAuth(AuthMethods::DIGEST);
    });
    assert_eq!(ran.result, Ok(()));
    let text = String::from_utf8_lossy(&ran.request).into_owned();
    let probe = format!(
        "POST /a HTTP/1.1\r\nHost: 127.0.0.1:{PORT}\r\nUser-Agent: curl/test\r\nAccept: */*\r\n\
         Content-Length: 0\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\n"
    );
    let answered = format!(
        "POST /a HTTP/1.1\r\nHost: 127.0.0.1:{PORT}\r\nAuthorization: Digest username=\"u\", \
         realm=\"r\", nonce=\"n\", uri=\"/a\", response=\"266f94b66eec4bb4c8730502a50fcec6\"\r\n\
         User-Agent: curl/test\r\nAccept: */*\r\nContent-Length: 3\r\n\
         Content-Type: application/x-www-form-urlencoded\r\n\r\na=b"
    );
    assert_eq!(text, probe + &answered);
    assert_eq!(ran.seen.body(), b"ok\n");
    let report = ran.easy.report();
    assert_eq!(report.auth_used(), AuthMethods::DIGEST);
    assert_eq!(report.sizes().upload(), 3);
    assert!(
        ran.seen
            .text()
            .contains(&"Server auth using Digest with user 'u'\n".to_string())
    );
}

/// A probe a server lets through without asking for credentials is made
/// again with its body, and authenticates no further (test 175).
#[test]
fn a_probe_let_through_is_made_again_with_its_body() {
    let (mut m, talk, _) = server(&[OK, OK], false);
    let ran = get(&mut m, "/a", talk, |o| {
        o.method = Method::Post;
        o.upload = UploadSource::Bytes(curl_alloc::TryRc::try_new(b"a=b".to_vec()).unwrap());
        o.login = crate::options::Login::from_pair(b"u:p").unwrap();
        o.http.auth = crate::options::HttpAuth(AuthMethods::DIGEST);
    });
    assert_eq!(ran.result, Ok(()));
    let text = String::from_utf8_lossy(&ran.request).into_owned();
    assert_eq!(text.matches("POST /a ").count(), 2, "{text}");
    assert!(text.contains("Content-Length: 0\r\n"), "{text}");
    assert!(text.contains("Content-Length: 3\r\n"), "{text}");
    assert!(text.ends_with("\r\n\r\na=b"), "{text}");
    assert!(!text.contains("Authorization"), "{text}");
    assert_eq!(ran.seen.body(), b"ok\n");
}

/// A second 401 with a new nonce not called stale refuses the answer:
/// the transfer ends there with the 401. Called stale, the request is
/// answered again, the count started over (tests 65 and 153).
#[test]
fn a_digest_answer_refused_ends_the_transfer() {
    let again = b"HTTP/1.1 401 No\r\nWWW-Authenticate: Digest realm=\"r\", nonce=\"m\"\r\n\
        Content-Length: 3\r\n\r\nno\n";
    let (mut m, talk, _) = server(&[DIGEST_CHALLENGE, again, OK], false);
    let ran = get(&mut m, "/a", talk, |o| {
        o.login = crate::options::Login::from_pair(b"u:p").unwrap();
        o.http.auth = crate::options::HttpAuth(AuthMethods::DIGEST);
    });
    assert_eq!(ran.result, Ok(()));
    let text = String::from_utf8_lossy(&ran.request).into_owned();
    assert_eq!(text.matches("GET /a ").count(), 2, "{text}");
    assert!(
        text.contains("nonce=\"n\", uri=\"/a\", response=\"544c035f0f40d9ebf0295157d8041f8c\"")
    );
    assert_eq!(ran.seen.body(), b"no\n");
    assert!(
        ran.seen
            .text()
            .contains(&"Digest authentication problem, ignoring.\n".to_string())
    );

    let stale = b"HTTP/1.1 401 No\r\nWWW-Authenticate: Digest realm=\"r\", nonce=\"m\", \
        stale=true\r\nContent-Length: 0\r\n\r\n";
    let (mut m, talk, _) = server(&[DIGEST_CHALLENGE, stale, OK], false);
    let ran = get(&mut m, "/a", talk, |o| {
        o.login = crate::options::Login::from_pair(b"u:p").unwrap();
        o.http.auth = crate::options::HttpAuth(AuthMethods::DIGEST);
    });
    assert_eq!(ran.result, Ok(()));
    let text = String::from_utf8_lossy(&ran.request).into_owned();
    assert_eq!(text.matches("GET /a ").count(), 3, "{text}");
    assert!(text.contains("nonce=\"m\""), "{text}");
    assert_eq!(ran.seen.body(), b"ok\n");
}

/// Digest goes beside the application's own Authorization, as C's does:
/// only Basic and Bearer give way to it.
#[test]
fn digest_goes_beside_the_application_s_authorization() {
    let (mut m, talk, _) = server(&[DIGEST_CHALLENGE, OK], false);
    let ran = get(&mut m, "/a", talk, |o| {
        o.http.headers = UserHeaders::new([&b"Authorization: mine"[..]]).unwrap();
        o.login = crate::options::Login::from_pair(b"u:p").unwrap();
        o.http.auth = crate::options::HttpAuth(AuthMethods::DIGEST);
    });
    assert_eq!(ran.result, Ok(()));
    let text = String::from_utf8_lossy(&ran.request).into_owned();
    let second = &text[text.rfind("GET /a ").unwrap()..];
    assert!(
        second.contains("Authorization: Digest username=\"u\""),
        "{second}"
    );
    assert!(second.contains("Authorization: mine\r\n"), "{second}");
}

/// What a request uploads is counted from nothing: a POST a 307 sends on
/// reports its body once (`Curl_pgrsReset`, test 579).
#[test]
fn each_request_counts_its_own_upload() {
    let ran = redirected(307, Method::Post, b"a=b", |_| {});
    assert_eq!(ran.result, Ok(()));
    assert_eq!(ran.easy.report().sizes().upload(), 3);
}

/// A token goes as Bearer when Bearer alone is wanted, its user named
/// as empty; a 401 offering Bearer again refuses it.
#[test]
fn a_token_goes_as_bearer() {
    let refused = b"HTTP/1.1 401 No\r\nWWW-Authenticate: Bearer\r\nContent-Length: 0\r\n\r\n";
    for (reply, result) in [(OK, Ok(())), (&refused[..], Ok(()))] {
        let (mut m, talk, _) = server(&[reply], false);
        let ran = get(&mut m, "/a", talk.clone(), |o| {
            o.login.bearer = Some(b"mF_9.B5f".to_vec());
            o.http.auth = crate::options::HttpAuth(AuthMethods::BEARER);
        });
        assert_eq!(ran.result, result);
        let received = talk.received();
        assert!(fixture::find(&received, b"Authorization: Bearer mF_9.B5f\r\n").is_some());
        let text = ran.seen.text();
        assert!(text.contains(&"Server auth using Bearer with user ''\n".to_string()));
        let problem = "Bearer authentication problem, ignoring.\n".to_string();
        assert_eq!(text.contains(&problem), reply != OK);
        assert_eq!(ran.easy.report().auth_used(), AuthMethods::BEARER);
    }
}

/// A `.netrc` file gives the host's credentials where the options give
/// none; a missing one is passed over if optional and fails the
/// transfer if required; an entry not found is passed over either way.
#[test]
fn a_netrc_file_gives_the_host_s_credentials() {
    use crate::options::NetrcMode;
    let path = std::env::temp_dir().join(format!("curl-core-netrc-{}", std::process::id()));
    std::fs::write(&path, b"machine 127.0.0.1 login nu password np\n").unwrap();
    let file = path.as_os_str().as_encoded_bytes().to_vec();
    let missing = [&file[..], b".missing"].concat();
    let none = Ok(());
    let read_error = Err(ErrorKind::ReadError);
    for (mode, file, login, url_user, result, sent) in [
        (
            NetrcMode::Required,
            &file,
            None,
            "",
            &none,
            Some("bnU6bnA="),
        ),
        (
            NetrcMode::Optional,
            &file,
            None,
            "",
            &none,
            Some("bnU6bnA="),
        ),
        (NetrcMode::Ignored, &file, None, "", &none, None),
        (
            NetrcMode::Required,
            &file,
            Some(&b"o:p"[..]),
            "",
            &none,
            Some("bzpw"),
        ),
        // The URL's user names the entry, which has no other.
        (
            NetrcMode::Required,
            &file,
            None,
            "other@",
            &none,
            Some("b3RoZXI6"),
        ),
        (NetrcMode::Optional, &missing, None, "", &none, None),
        (NetrcMode::Required, &missing, None, "", &read_error, None),
    ] {
        let (mut m, talk, _) = server(&[OK], false);
        let url = format!("http://{url_user}127.0.0.1:{PORT}/a");
        let ran = get(&mut m, "/a", talk.clone(), |o| {
            o.set_url(Some(url.as_bytes())).unwrap();
            o.netrc.mode = mode;
            o.netrc.file = Some(file.clone());
            if let Some(pair) = login {
                o.login = crate::options::Login::from_pair(pair).unwrap();
            }
        });
        assert_eq!(&ran.result, result, "{mode:?} {login:?} {url_user}");
        let received = talk.received();
        let line = sent.map(|token| format!("Authorization: Basic {token}\r\n"));
        match &line {
            Some(line) => assert!(
                fixture::find(&received, line.as_bytes()).is_some(),
                "{mode:?} {login:?} {url_user}: {}",
                String::from_utf8_lossy(&received)
            ),
            None => assert!(fixture::find(&received, b"Authorization").is_none()),
        }
        let text = ran.seen.text();
        if file == &missing {
            let said = if result.is_ok() {
                format!(
                    "Could not find host 127.0.0.1 in the {} file; using defaults\n",
                    String::from_utf8_lossy(&missing)
                )
            } else {
                ".netrc error: no such file\n".to_string()
            };
            assert!(text.contains(&said), "{text:?}");
        }
    }
    std::fs::remove_file(&path).unwrap();
}

/// Basic sent and offered again is refused: the 401 is the answer, and
/// fails a request that asked to fail on errors. Without credentials, a
/// 401 is no different from any other error.
#[test]
fn a_401_to_credentials_sent_is_the_answer() {
    for (login, fail_on_error, result) in [
        (true, false, Ok(())),
        (true, true, Err(ErrorKind::HttpReturnedError)),
        (false, true, Err(ErrorKind::HttpReturnedError)),
        (false, false, Ok(())),
    ] {
        let (mut m, talk, _) = server(&[CHALLENGE, OK], false);
        let ran = get(&mut m, "/a", talk.clone(), |o| {
            if login {
                o.login = crate::options::Login::from_pair(b"u:p").unwrap();
            }
            o.http.fail_on_error = fail_on_error;
        });
        assert_eq!(ran.result, result, "login {login}, -f {fail_on_error}");
        let received = talk.received();
        assert_eq!(
            fixture::find(&received, b"Authorization: Basic dTpw").is_some(),
            login
        );
        assert_eq!(ran.easy.report().redirects(), 0);
        let problem = "Basic authentication problem, ignoring.\n".to_string();
        assert_eq!(ran.seen.text().contains(&problem), login);
        if !fail_on_error {
            assert_eq!(ran.seen.body(), b"nope\n");
        }
    }
}

/// A `Location:` with a code outside 3xx is not followed, only kept.
#[test]
fn a_location_outside_a_redirect_is_not_followed() {
    let created = b"HTTP/1.1 201 Created\r\nLocation: /b\r\nContent-Length: 3\r\n\r\nok\n";
    let (mut m, talk, _) = server(&[created, OK], false);
    let ran = get(&mut m, "/a", talk, |o| o.http.follow = Follow::All);
    assert_eq!(ran.result, Ok(()));
    assert_eq!(ran.request, request_of("/a"));
    assert_eq!(ran.seen.body(), b"ok\n");
    let shown = format!("http://127.0.0.1:{PORT}/b");
    assert_eq!(ran.easy.report().redirect_url(), Some(shown.as_bytes()));
}

fn redirect(code: u16, location: &str) -> Vec<u8> {
    format!("HTTP/1.1 {code} Moved\r\nLocation: {location}\r\nContent-Length: 0\r\n\r\n")
        .into_bytes()
}

/// The two requests a transfer asking `method` with `body` sends when a
/// `code` sends it on to `/b`, as `set` has it follow.
fn redirected(code: u16, method: Method, body: &[u8], set: impl FnOnce(&mut Options)) -> Ran {
    let first = redirect(code, "/b");
    let (mut m, talk, _) = server(&[&first, OK], false);
    let body = body.to_vec();
    get(&mut m, "/a", talk, |o| {
        o.method = method;
        o.upload = UploadSource::Bytes(curl_alloc::TryRc::try_new(body).unwrap());
        o.http.follow = Follow::All;
        set(o);
    })
}

/// The second request on the wire, its line and its head.
fn second_request(ran: &Ran) -> String {
    let text = String::from_utf8_lossy(&ran.request).into_owned();
    let at = text.find(" /b HTTP/1.1").expect("the redirect is followed");
    // The method before it, behind the first request's body.
    let start = text[..at]
        .trim_end_matches(|c: char| c.is_ascii_uppercase())
        .len();
    text[start..].to_string()
}

/// A POST redirected by a 301 or 302 is made a GET, without a word unless
/// the code is obeyed; a 303 makes anything a GET. POSTREDIR keeps a POST.
#[test]
fn a_redirect_turns_a_post_into_a_get_as_c_does() {
    for code in [301, 302, 303] {
        let ran = redirected(code, Method::Post, b"a=b", |_| {});
        assert_eq!(ran.result, Ok(()));
        let second = second_request(&ran);
        assert!(
            second.starts_with("GET /b HTTP/1.1\r\n"),
            "{code}: {second}"
        );
        assert!(!second.contains("Content-Length"), "{second}");
        assert_eq!(ran.easy.effective_method(), b"GET");
        let said = format!("Switch to GET because of {code} response\n");
        assert!(!ran.seen.text().contains(&said));

        let ran = redirected(code, Method::Post, b"a=b", |o| {
            o.http.follow = Follow::ObeyCode
        });
        assert!(ran.seen.text().contains(&said), "{code}");

        let keep = PostRedir {
            post301: code == 301,
            post302: code == 302,
            post303: code == 303,
        };
        let ran = redirected(code, Method::Post, b"a=b", |o| o.http.post_redirect = keep);
        let second = second_request(&ran);
        assert!(
            second.starts_with("POST /b HTTP/1.1\r\n"),
            "{code}: {second}"
        );
        assert!(
            second.ends_with("\r\n\r\na=b"),
            "the body goes again: {second}"
        );
        assert_eq!(ran.easy.effective_method(), b"POST");
    }
    // A PUT stays one but on a 303; a 307 changes nothing.
    let put = |code| second_request(&redirected(code, Method::Upload, b"x", |_| {}));
    assert!(put(301).starts_with("PUT /b "));
    assert!(put(303).starts_with("GET /b "));
    assert!(put(307).starts_with("PUT /b "));
    // A HEAD stays bodyless.
    let head = second_request(&redirected(303, Method::Head, b"", |_| {}));
    assert!(head.starts_with("HEAD /b "), "{head}");
    let post = second_request(&redirected(307, Method::Post, b"a=b", |_| {}));
    assert!(
        post.starts_with("POST /b ") && post.ends_with("a=b"),
        "{post}"
    );
}

/// A custom method sticks across a switch to GET, said so, unless the
/// code is obeyed; asking it only of the first URL drops it at once.
#[test]
fn a_custom_method_follows_as_the_mode_says() {
    let custom = |o: &mut Options| o.http.custom_method = Some(b"DELETE".to_vec());
    let ran = redirected(303, Method::Get, b"", custom);
    assert!(second_request(&ran).starts_with("DELETE /b "));
    assert!(
        ran.seen
            .text()
            .contains(&"Stick to DELETE instead of GET\n".to_string())
    );
    assert_eq!(ran.easy.effective_method(), b"DELETE");

    let ran = redirected(303, Method::Get, b"", |o| {
        custom(o);
        o.http.follow = Follow::ObeyCode;
    });
    assert!(second_request(&ran).starts_with("GET /b "));
    assert!(
        ran.seen
            .text()
            .contains(&"Switch to GET because of 303 response\n".to_string())
    );
    assert_eq!(
        ran.easy.effective_method(),
        b"DELETE",
        "named as C names it"
    );

    let ran = redirected(307, Method::Get, b"", |o| {
        custom(o);
        o.http.follow = Follow::FirstOnly;
    });
    assert!(ran.request.starts_with(b"DELETE /a "));
    assert!(second_request(&ran).starts_with("GET /b "));
    let text = ran.seen.text();
    assert!(text.contains(&"Drop custom request method for next request\n".to_string()));
}

/// A body read from a handler, `data`, started over by its rewind
/// handler if it has one; counts its rewinds.
#[derive(Clone)]
struct Stream {
    data: &'static [u8],
    at: Rc<std::cell::Cell<usize>>,
    rewinds: Rc<std::cell::Cell<u32>>,
}

impl Stream {
    fn new(data: &'static [u8]) -> Stream {
        Stream {
            data,
            at: Rc::default(),
            rewinds: Rc::default(),
        }
    }

    fn source(&self, rewinds: bool) -> UploadSource {
        UploadSource::Read {
            handler: Handler::read(self.clone()).unwrap(),
            rewind: rewinds.then(|| Handler::rewind(self.clone()).unwrap()),
            size: Some(self.data.len() as u64),
        }
    }
}

impl crate::handler::ReadHandler for Stream {
    fn read(&self, _: &mut TransferCx<'_>, buf: &mut [u8]) -> crate::handler::Read {
        let rest = &self.data[self.at.get()..];
        let n = rest.len().min(buf.len());
        buf[..n].copy_from_slice(&rest[..n]);
        self.at.set(self.at.get() + n);
        match std::num::NonZeroUsize::new(n) {
            Some(n) => crate::handler::Read::Data(n),
            None => crate::handler::Read::Eof,
        }
    }
}

impl crate::handler::Rewind for Stream {
    fn rewind(&self, _: &mut TransferCx<'_>) -> Result<(), crate::handler::RewindFailed> {
        self.at.set(0);
        self.rewinds.set(self.rewinds.get() + 1);
        Ok(())
    }
}

/// A body read from a handler is started over for the next request, or
/// the transfer fails if it cannot be: unless that request sends none.
#[test]
fn a_redirected_body_is_rewound_or_the_transfer_fails() {
    let stream = Stream::new(b"body");
    let ran = redirected(307, Method::Upload, b"", |o| o.upload = stream.source(true));
    assert_eq!(ran.result, Ok(()));
    assert_eq!(stream.rewinds.get(), 1);
    assert!(second_request(&ran).ends_with("\r\n\r\nbody"));
    let text = ran.seen.text();
    let need = text
        .iter()
        .position(|l| l == "Need to rewind upload for next request\n");
    let location = ran
        .seen
        .of("in")
        .iter()
        .position(|l| l.starts_with(b"Location:"));
    assert!(need.is_some() && location.is_some(), "{text:?}");

    let stream = Stream::new(b"body");
    let ran = redirected(307, Method::Upload, b"", |o| {
        o.upload = stream.source(false)
    });
    assert_eq!(ran.result, Err(ErrorKind::SendFailRewind));
    assert!(
        ran.seen
            .text()
            .contains(&"necessary data rewind was not possible\n".to_string())
    );
    assert!(!ran.request.windows(6).any(|w| w == b"PUT /b"));

    // A GET sends nothing again.
    let stream = Stream::new(b"body");
    let ran = redirected(303, Method::Upload, b"", |o| {
        o.upload = stream.source(false)
    });
    assert_eq!(ran.result, Ok(()));
    assert!(second_request(&ran).starts_with("GET /b "));
}

/// After a response in HTTP/1.0, the transfer's requests say HTTP/1.0;
/// a body of unknown size cannot go chunked to it.
#[test]
fn a_response_in_http_1_0_makes_the_next_request_one() {
    let first = b"HTTP/1.0 301 Moved\r\nLocation: /b\r\nConnection: keep-alive\r\nContent-Length: 0\r\n\r\n";
    let (mut m, talk, _) = server(&[first, OK], false);
    let ran = get(&mut m, "/a", talk, |o| o.http.follow = Follow::All);
    assert_eq!(ran.result, Ok(()));
    let text = String::from_utf8_lossy(&ran.request).into_owned();
    assert!(text.contains("GET /b HTTP/1.0\r\n"), "{text}");

    let stream = Stream::new(b"body");
    let (mut m, talk, _) = server(&[first, OK], false);
    let ran = get(&mut m, "/a", talk, |o| {
        o.http.follow = Follow::All;
        o.method = Method::Upload;
        o.upload = UploadSource::Read {
            handler: Handler::read(stream.clone()).unwrap(),
            rewind: Some(Handler::rewind(stream.clone()).unwrap()),
            size: None,
        };
    });
    assert_eq!(ran.result, Err(ErrorKind::UploadFailed));
    // The body waited for a 100: nothing was read, nothing is rewound.
    assert_eq!(stream.rewinds.get(), 0);
    assert!(!String::from_utf8_lossy(&ran.request).contains("/b HTTP"));
}

/// A request made again on a fresh connection sends its body from the
/// start, its handler rewound (`FOLLOW_RETRY`).
#[test]
fn a_retried_request_rewinds_its_body() {
    let first = answers_once();
    let fresh = Conversation::new(OK, false);
    let mut m = serving(Peer::Accepts, &[&first, &fresh]);
    assert_eq!(get(&mut m, "/a", first.clone(), |_| {}).result, Ok(()));
    let stream = Stream::new(b"body");
    let ran = get(&mut m, "/b", fresh.clone(), |o| {
        o.method = Method::Upload;
        o.upload = stream.source(true);
    });
    assert_eq!(ran.result, Ok(()));
    assert_eq!(stream.rewinds.get(), 1);
    let sent = fresh.received();
    assert!(
        sent.starts_with(b"PUT /b ") && sent.ends_with(b"\r\n\r\nbody"),
        "{}",
        String::from_utf8_lossy(&sent)
    );
}

/// A redirect followed with the auto-referer sends the URL it came from,
/// without credentials or fragment, in place of the application's
/// referer; without it, the application's goes again.
#[test]
fn a_followed_redirect_refers_to_where_it_came_from() {
    for auto in [false, true] {
        let first = redirect(302, "/b");
        let (mut m, talk, _) = server(&[&first, OK], false);
        let url = format!("http://u:p@127.0.0.1:{PORT}/a?q#frag");
        let ran = get(&mut m, "/a", talk, |o| {
            o.set_url(Some(url.as_bytes())).unwrap();
            o.http.follow = Follow::All;
            o.http.auto_referer = auto;
            o.http.referer = Some(b"given".to_vec());
        });
        assert_eq!(ran.result, Ok(()));
        let text = String::from_utf8_lossy(&ran.request).into_owned();
        let (first, second) = text.split_at(text.find("GET /b ").unwrap());
        assert!(first.contains("Referer: given\r\n"), "{first}");
        let want = if auto {
            format!("http://127.0.0.1:{PORT}/a?q")
        } else {
            "given".to_string()
        };
        assert!(second.contains(&format!("Referer: {want}\r\n")), "{second}");
        assert_eq!(ran.easy.report().referer(), Some(want.as_bytes()));
    }
}

/// Credentials in the URL a redirect leads to go to its host, wherever
/// the transfer started; those of the first URL go no further than it.
#[test]
fn a_redirect_s_own_credentials_go_with_it() {
    for (location, sent) in [
        (format!("http://u:p@other.test:{PORT}/b"), true),
        (format!("http://other.test:{PORT}/b"), false),
    ] {
        let first = Conversation::new(&moved(&location, true), true);
        let second = Conversation::new(OK, false);
        let mut m = serving(Peer::Accepts, &[&first, &second]);
        let entry = format!("other.test:{PORT}:127.0.0.1");
        let url = format!("http://x:y@127.0.0.1:{PORT}/a");
        let ran = get(&mut m, "/a", first.clone(), |o| {
            o.set_url(Some(url.as_bytes())).unwrap();
            o.http.follow = Follow::All;
            o.resolve.set([entry.as_bytes()]).unwrap();
        });
        assert_eq!(ran.result, Ok(()));
        let has = |r: &[u8], line: &[u8]| fixture::find(r, line).is_some();
        assert!(has(&first.received(), b"Authorization: Basic eDp5\r\n"));
        let second = second.received();
        assert_eq!(
            has(&second, b"Authorization: Basic dTpw\r\n"),
            sent,
            "{location}"
        );
        assert!(!has(&second, b"Basic eDp5"), "the first URL's stay");
    }
}

/// A 417 to a body held for a 100 has the request made again on the
/// kept connection, without `Expect`, counted as a redirect; the
/// library adds no `Expect` after.
#[test]
fn a_417_has_the_request_made_again_without_expect() {
    let refused = b"HTTP/1.1 417 Expectation Failed\r\nContent-Length: 0\r\n\r\n";
    let (mut m, talk, _) = server(&[refused, OK], false);
    let body = vec![b'x'; 2 * 1024 * 1024];
    let ran = get(&mut m, "/a", talk, |o| {
        o.method = Method::Upload;
        o.upload = UploadSource::Bytes(curl_alloc::TryRc::try_new(body).unwrap());
    });
    assert_eq!(ran.result, Ok(()));
    let text = String::from_utf8_lossy(&ran.request).into_owned();
    let second = text.rfind("PUT /a HTTP/1.1").unwrap();
    assert!(text[..second].contains("Expect: 100-continue\r\n"));
    assert!(text[..second].ends_with("\r\n\r\n"), "no body went first");
    assert!(
        !text[second..].contains("Expect:"),
        "{}",
        &text[second..second + 200]
    );
    assert_eq!(
        text.len() - text[second..].find("\r\n\r\n").unwrap() - second - 4,
        2 * 1024 * 1024
    );
    let said = ran.seen.text();
    assert!(said.contains(&"Got HTTP failure 417 while waiting for a 100\n".to_string()));
    let report = ran.easy.report();
    assert_eq!((report.redirects(), report.connects()), (1, 1));
}

/// A URL the application keeps is read as each transfer starts, as it
/// is then; setting it drops the URL given as text.
#[test]
fn a_shared_url_is_read_as_each_transfer_starts() {
    let text = format!("http://127.0.0.1:{PORT}/one");
    let shared = crate::url::SharedUrl::new(
        crate::url::Url::parse(text.as_bytes(), Default::default()).unwrap(),
    )
    .unwrap();
    let (mut m, talk, _) = server(&[OK, OK], false);
    let ran = get(&mut m, "/ignored", talk.clone(), |o| {
        o.set_shared_url(Some(shared.clone()));
        assert_eq!(o.url(), None);
    });
    assert_eq!(ran.result, Ok(()));
    assert!(ran.request.starts_with(b"GET /one HTTP/1.1\r\n"));
    shared.update(|u| {
        u.set(crate::url::Part::Path, Some(b"/two"), Default::default())
            .unwrap()
    });
    let ran = get(&mut m, "/ignored", talk.clone(), |o| {
        o.set_shared_url(Some(shared.clone()))
    });
    assert!(fixture::find(&ran.request, b"GET /two HTTP/1.1\r\n").is_some());
}

/// The application's port goes over the first URL's and a relative
/// redirect's, not over the port of an absolute one.
#[test]
fn the_application_s_port_holds_until_an_absolute_redirect() {
    let relative = redirect(302, "/b");
    let (mut m, talk, _) = server(&[&relative, OK], false);
    let ran = get(&mut m, "/a", talk, |o| {
        o.set_url(Some(b"http://127.0.0.1:1/a")).unwrap();
        o.port = std::num::NonZeroU16::new(PORT);
        o.http.follow = Follow::All;
    });
    assert_eq!(ran.result, Ok(()));
    assert!(second_request(&ran).starts_with("GET /b "));

    let absolute = redirect(302, "http://127.0.0.1:1/c");
    let (mut m, talk, _) = server(&[&absolute, OK], false);
    let ran = get(&mut m, "/a", talk, |o| {
        o.set_url(Some(b"http://127.0.0.1:1/a")).unwrap();
        o.port = std::num::NonZeroU16::new(PORT);
        o.http.follow = Follow::All;
    });
    assert_eq!(
        ran.result,
        Err(ErrorKind::CouldntConnect),
        "port 1 is asked for"
    );
}

/// A redirect that sets a cookie.
const SETS_A_COOKIE: &[u8] = b"HTTP/1.1 302 Moved\r\nLocation: /b\r\n\
    Set-Cookie: a=1; path=/\r\nContent-Length: 0\r\n\r\n";

/// A cookie a response sets goes with the next request, before the
/// application's own; the jar says it stored it before the line is traced
/// (`http_header`, then `Curl_debug`).
#[test]
fn a_cookie_set_goes_with_the_next_request() {
    let (mut m, talk, _) = server(&[SETS_A_COOKIE, OK], false);
    let ran = get(&mut m, "/a", talk, |o| {
        o.http.follow = Follow::All;
        // An empty name reads nothing, but turns the jar on.
        o.http.cookies.files.push(b"").unwrap();
        o.http.cookies.send = Some(b"app=2".to_vec());
    });
    assert_eq!(ran.result, Ok(()));
    let text = String::from_utf8_lossy(&ran.request).into_owned();
    let (first, second) = text.split_at(text.find("GET /b ").unwrap());
    assert!(first.contains("\r\nCookie: app=2\r\n"), "{first}");
    assert!(second.contains("\r\nCookie: a=1; app=2\r\n"), "{second}");
    let seen = ran.seen.0.borrow();
    let added = seen
        .iter()
        .position(|(w, b)| *w == "text" && b.starts_with(b"Added cookie a="));
    let line = seen
        .iter()
        .position(|(w, b)| *w == "in" && b.starts_with(b"Set-Cookie:"));
    assert!(added.is_some() && added < line, "{added:?} {line:?}");
}

/// Without the jar on, a server's cookies are not kept.
#[test]
fn no_jar_keeps_no_cookies() {
    let (mut m, talk, _) = server(&[SETS_A_COOKIE, OK], false);
    let mut ran = get(&mut m, "/a", talk, |o| o.http.follow = Follow::All);
    assert_eq!(ran.result, Ok(()));
    let text = String::from_utf8_lossy(&ran.request).into_owned();
    assert!(!text.contains("Cookie:"), "{text}");
    assert_eq!(ran.easy.cookie_list().unwrap(), Vec::<Vec<u8>>::new());
}

/// A custom `Host:` names the cookies' host, without its port
/// (`req.cookiehost`).
#[test]
fn a_custom_host_names_the_cookies_host() {
    let reply = b"HTTP/1.1 200 OK\r\nSet-Cookie: a=1\r\nContent-Length: 0\r\n\r\n";
    let (mut m, talk, _) = server(&[reply], false);
    let mut ran = get(&mut m, "/d/e", talk, |o| {
        o.http.headers = UserHeaders::new([&b"Host: other.example:99"[..]]).unwrap();
        o.http.cookies.files.push(b"").unwrap();
    });
    assert_eq!(ran.result, Ok(()));
    assert_eq!(
        ran.easy.cookie_list().unwrap(),
        [b"other.example\tFALSE\t/d\tFALSE\t0\ta\t1".to_vec()]
    );
}

/// One request stores 50 `Set-Cookie:` lines at most; the next request
/// stores its own 50 (`MAX_SET_COOKIE_AMOUNT`, per request).
#[test]
fn a_request_stores_50_cookies_at_most() {
    let mut many = b"HTTP/1.1 302 Moved\r\nLocation: /b\r\n".to_vec();
    for i in 0..60 {
        many.extend_from_slice(format!("Set-Cookie: a{i}=1\r\n").as_bytes());
    }
    let mut more = b"HTTP/1.1 200 OK\r\n".to_vec();
    for i in 0..60 {
        more.extend_from_slice(format!("Set-Cookie: b{i}=1\r\n").as_bytes());
    }
    many.extend_from_slice(b"Content-Length: 0\r\n\r\n");
    more.extend_from_slice(b"Content-Length: 0\r\n\r\n");
    let (mut m, talk, _) = server(&[&many, &more], false);
    let mut ran = get(&mut m, "/a", talk, |o| {
        o.http.follow = Follow::All;
        o.http.cookies.files.push(b"").unwrap();
    });
    assert_eq!(ran.result, Ok(()));
    let list = ran.easy.cookie_list().unwrap();
    let count = |prefix: u8| {
        list.iter()
            .filter(|l| l.split(|&b| b == b'\t').nth(5).unwrap()[0] == prefix)
            .count()
    };
    assert_eq!((count(b'a'), count(b'b')), (50, 50));
}

/// Handles given a share that keeps cookies use its jar: a cookie one
/// stores, the other lists and saves; a share that does not keep them
/// leaves each its own.
#[test]
fn a_share_keeps_cookies_for_its_handles() {
    let line = b"example.com\tFALSE\t/\tFALSE\t0\ta\t1";
    let share = crate::share::Share::new().unwrap();
    let mut one = Easy::new();
    let mut two = Easy::new();
    one.set_share(Some(share.clone()));
    two.set_share(Some(share.clone()));
    one.add_cookie(line).unwrap();
    assert!(two.cookie_list().unwrap().is_empty(), "each its own");
    share.keep_cookies();
    one.add_cookie(line).unwrap();
    assert_eq!(two.cookie_list().unwrap(), [line.to_vec()]);
    // Saved only once a transfer started the jar; reading files does.
    let dir = std::env::temp_dir().join(format!("curl-share-jar-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let jar = dir.join("jar");
    two.options_mut().http.cookies.save_to = Some(jar.as_os_str().as_encoded_bytes().to_vec());
    two.save_cookies().unwrap();
    assert!(!jar.exists(), "no transfer started it");
    two.options_mut().http.cookies.files.push(b"").unwrap();
    two.reload_cookies().unwrap();
    two.save_cookies().unwrap();
    let saved = std::fs::read(&jar).unwrap();
    assert!(saved.ends_with(b"\n\nexample.com\tFALSE\t/\tFALSE\t0\ta\t1\n"));
    std::fs::remove_dir_all(&dir).unwrap();
}

/// `Last-Modified` gives the file time when it is asked for, and not from
/// a response that has no body (`http_header_l`); one that cannot be read
/// is the epoch.
#[test]
fn last_modified_gives_the_file_time_when_asked() {
    const DATED: &[u8] = b"HTTP/1.1 200 OK\r\nLast-Modified: Tue, 13 Jun 2000 12:10:00 GMT\r\n\
                           Content-Length: 0\r\n\r\n";
    let (mut m, talk, _) = server(&[DATED], false);
    let ran = get(&mut m, "/a", talk, |o| o.filetime = true);
    assert_eq!(ran.result, Ok(()));
    assert_eq!(ran.easy.report().filetime(), Some(960_898_200));

    let (mut m, talk, _) = server(&[DATED], false);
    let ran = get(&mut m, "/a", talk, |_| {});
    assert_eq!(ran.easy.report().filetime(), None);

    let unmodified =
        b"HTTP/1.1 304 Not Modified\r\nLast-Modified: Tue, 13 Jun 2000 12:10:00 GMT\r\n\r\n";
    let (mut m, talk, _) = server(&[unmodified], false);
    let ran = get(&mut m, "/a", talk, |o| o.filetime = true);
    assert_eq!(ran.easy.report().filetime(), None);

    let garbled = b"HTTP/1.1 200 OK\r\nLast-Modified: whenever\r\nContent-Length: 0\r\n\r\n";
    let (mut m, talk, _) = server(&[garbled], false);
    let ran = get(&mut m, "/a", talk, |o| o.filetime = true);
    assert_eq!(ran.easy.report().filetime(), Some(0));
}

/// Handles on a share that keeps cookies use its jar in whichever multi
/// runs them: what one transfer stores, the next sends.
#[test]
fn a_share_s_jar_serves_the_transfers_of_a_multi() {
    let share = crate::share::Share::new().unwrap();
    share.keep_cookies();
    let jar_on = |o: &mut Options| o.http.cookies.files.push(b"").unwrap();
    let (mut m, talk, _) = server(&[SETS_A_COOKIE], false);
    let mut one = Easy::new();
    one.set_share(Some(share.clone()));
    assert_eq!(get_with(&mut m, one, "/a", talk, jar_on).result, Ok(()));
    let (mut m, talk, _) = server(&[OK], false);
    let mut two = Easy::new();
    two.set_share(Some(share.clone()));
    let ran = get_with(&mut m, two, "/a", talk, jar_on);
    assert_eq!(ran.result, Ok(()));
    let text = String::from_utf8_lossy(&ran.request).into_owned();
    assert!(text.contains("\r\nCookie: "), "{text}");
}

/// Through a proxy that sends it on, a request names the whole URL,
/// without its fragment or credentials, asks to keep the connection to
/// the proxy, and keeps the origin's `Host:` (`http_target`); the
/// connection is the proxy's.
#[test]
fn a_forwarding_proxy_gets_the_whole_url() {
    let (mut m, talk, _) = server(&[OK], false);
    let ran = get(&mut m, "/", talk, |o| {
        o.set_url(Some(b"http://user:pw@origin.example:80/a?b#c"))
            .unwrap();
        o.proxy.url = Some(format!("127.0.0.1:{PORT}").into_bytes());
    });
    assert_eq!(ran.result, Ok(()));
    let text = String::from_utf8_lossy(&ran.request).into_owned();
    assert!(
        text.starts_with(
            "GET http://origin.example/a?b HTTP/1.1\r\nHost: origin.example\r\n\
             Authorization: Basic dXNlcjpwdw==\r\n"
        ),
        "{text}"
    );
    assert!(
        text.ends_with("Proxy-Connection: Keep-Alive\r\n\r\n"),
        "{text}"
    );
    assert!(ran.easy.report().used_proxy());
    let left = format!("Connection #0 to host 127.0.0.1:{PORT} left intact\n");
    assert!(ran.seen.text().contains(&left), "{:?}", ran.seen.text());
}
