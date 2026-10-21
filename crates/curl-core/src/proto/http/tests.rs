use std::cell::RefCell;
use std::net::SocketAddr;
use std::num::NonZeroU64;
use std::rc::Rc;

use crate::conn::io::{Conversation, FakeNet, Peer};
use crate::easy::Easy;
use crate::error::ErrorKind;
use crate::handler::{
    DebugHandler, DebugKind, Handler, HeaderHandler, HeaderOrigin, Write, WriteHandler,
};
use crate::id::ArenaPolicy;
use crate::multi::{Env, Multi, NoEvents, PauseRequest, TransferCx, drive_to_completion};
use crate::options::{Method, Options, Resume, UserHeaders};
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
    let mut e = Easy::new();
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

/// Bytes after the last chunk are left over, and said so; none, nothing
/// is said.
#[test]
fn bytes_after_the_chunks_are_left_over() {
    let chunked = "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nok\r\n0\r\n\r\n";
    let ran = run("/", format!("{chunked}extra").as_bytes(), false, |_| {});
    assert_eq!((ran.result, ran.seen.body()), (Ok(()), b"ok".to_vec()));
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
    assert_eq!(r.retry_after(), 21600);
}

/// `Retry-After` in seconds; what is not a number is 0
/// (`http_header_r`).
#[test]
fn retry_after_reads_seconds() {
    let after = |line: &[u8]| framing::retry_after(line);
    assert_eq!(after(b"Retry-After: 22\r\n"), Some(22));
    assert_eq!(after(b"retry-after:\t 7x\r\n"), Some(7));
    assert_eq!(after(b"Retry-After: soon\r\n"), Some(0));
    assert_eq!(after(b"Retry-After: 99999999999999999999\r\n"), Some(0));
    assert_eq!(after(b"Retry-After: 21601\r\n"), Some(21600));
    assert_eq!(after(b"Retry-Afte: 1\r\n"), None);
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
