use std::net::SocketAddr;
use std::num::NonZeroU64;
use std::sync::Arc;
use std::sync::Mutex;
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
    AuthMethods, BufferSize, ColdGroup, Follow, MaxRedirects, Method, Options, PostRedir,
    Protocols, Resume, Schemes, UploadSource, UserHeaders,
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
struct Seen(Arc<Mutex<Vec<Saw>>>);

impl Seen {
    fn of(&self, what: &str) -> Vec<Vec<u8>> {
        self.0
            .lock()
            .unwrap()
            .iter()
            .filter(|(w, _)| *w == what)
            .map(|(_, b)| b.clone())
            .collect()
    }

    /// The trace's text lines, without the debug build's warning and
    /// the lines only it writes.
    fn text(&self) -> Vec<String> {
        self.of("text")
            .into_iter()
            .filter(|l| !crate::trace::debug_only(l))
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
        self.0.lock().unwrap().push(("body", body.to_vec()));
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
        self.0.lock().unwrap().push((what, line.to_vec()));
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
        self.0.lock().unwrap().push((what, data.to_vec()));
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
    let id = m.add(Box::new(e), (), &mut NoEvents).unwrap();
    let result = drive_to_completion(m, id, &mut NoEvents).unwrap();
    let easy = m.remove(id, &mut NoEvents).unwrap().easy;
    Ran {
        result,
        request: talk.received(),
        seen,
        easy: *easy,
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
            "using HTTP/1.x\n",
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
    got: Arc<Mutex<Vec<u8>>>,
    paused: Arc<crate::test_cell::Cell<bool>>,
}

impl WriteHandler for PausesOnce {
    fn write(&self, _: &mut TransferCx<'_>, body: &[u8]) -> Write {
        if !self.paused.replace(true) {
            return Write::Pause;
        }
        self.got.lock().unwrap().extend_from_slice(body);
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
        let id = m.add(Box::new(e), (), &mut NoEvents).unwrap();
        for _ in 0..4 {
            m.perform(&mut NoEvents).unwrap();
        }
        assert!(writer.paused.get(), "paused");
        assert!(m.info_read().is_none(), "not over while output is held");
        m.pause(id, PauseRequest::CONT, &mut NoEvents).unwrap();
        let result = drive_to_completion(&mut m, id, &mut NoEvents).unwrap();
        assert_eq!(result, Ok(()));
        assert_eq!(*writer.got.lock().unwrap(), b"abc", "{reply:?}");
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
        .lock()
        .unwrap()
        .iter()
        .filter(|(w, b)| matches!(*w, "text" | "header") && !crate::trace::debug_only(b))
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
        .lock()
        .unwrap()
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
        let seen = ran.seen.0.lock().unwrap();
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
            o.flow.make_mut().unwrap().max_filesize = std::num::NonZeroU64::new(10);
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
    calls: Arc<crate::test_cell::Cell<u32>>,
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
        calls: Arc::default(),
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
    let id = m.add(Box::new(e), (), &mut NoEvents).unwrap();
    m.perform(&mut NoEvents).unwrap();
    // The connect started in the first pass is taken in the next.
    m.perform(&mut NoEvents).unwrap();
    let waits = |m: &mut Multi| {
        let mut seen = Vec::new();
        m.sockets(&mut NoEvents, |_, events| seen.push(events));
        seen
    };
    assert_eq!(waits(&mut m), [Events::IN]);
    m.pause(id, PauseRequest::RECV, &mut NoEvents).unwrap();
    assert_eq!(waits(&mut m), []);
}

/// What an exchange waits for passes through its connection's layers: one
/// that writes while it reads (TLS) has the transfer wait to write too,
/// unless the transfer waits for nothing (`Curl_conn_adjust_pollset`).
#[test]
fn an_exchange_waits_for_what_its_layers_want() {
    use crate::conn::io::Events;
    use crate::conn::layer::testing::wants_out;
    use crate::deliver::PauseRequest;
    let (mut m, _talk, _clock) = server(&[], false);
    let mut e = Easy::new();
    let url = format!("http://127.0.0.1:{PORT}/");
    e.options_mut().set_url(Some(url.as_bytes())).unwrap();
    e.options_mut().layer = Some(wants_out);
    let id = m.add(Box::new(e), (), &mut NoEvents).unwrap();
    m.perform(&mut NoEvents).unwrap();
    // The connect started in the first pass is taken in the next.
    m.perform(&mut NoEvents).unwrap();
    let waits = |m: &mut Multi| {
        let mut seen = Vec::new();
        m.sockets(&mut NoEvents, |_, events| seen.push(events));
        seen
    };
    assert_eq!(waits(&mut m), [Events::IN | Events::OUT]);
    m.pause(id, PauseRequest::RECV, &mut NoEvents).unwrap();
    assert_eq!(waits(&mut m), []);
}

/// A connection's bytes go through its layers both ways: what a layer
/// makes of them is what the server is sent and the transfer reads.
#[test]
fn bytes_pass_through_the_connection_s_layers() {
    use crate::conn::layer::testing::upper;
    let ran = run(
        "/a",
        b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nabc",
        false,
        |o| {
            o.layer = Some(upper);
        },
    );
    assert_eq!(ran.result, Ok(()));
    assert_eq!(ran.request, request_of("/A").to_ascii_uppercase());
    assert_eq!(ran.seen.body(), b"ABC");
}

/// A read that would block while a layer holds bytes a poll cannot see
/// runs the transfer again at once, which then reads them
/// (`sendrecv_dl`'s `data_pending`): it does not wait on its socket.
#[test]
fn bytes_a_layer_holds_are_read_without_waiting() {
    use crate::conn::layer::testing::holdback;
    let ran = run(
        "/",
        b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nabc",
        false,
        |o| {
            o.layer = Some(holdback);
        },
    );
    assert_eq!(ran.result, Ok(()));
    assert_eq!(ran.seen.body(), b"abc");
}

/// An idle connection is asked down its layers whether it is alive before
/// it is reused (`Curl_conn_is_alive`): one a layer says is dead is
/// closed, and the request goes over a new one.
#[test]
fn an_idle_connection_a_layer_finds_dead_is_not_reused() {
    use crate::conn::layer::testing::dying;
    let first = Conversation::new(OK, false);
    let fresh = Conversation::new(OK, false);
    let mut m = serving(Peer::Accepts, &[&first, &fresh]);
    let one = get(&mut m, "/a", first.clone(), |o| o.layer = Some(dying));
    assert_eq!(one.result, Ok(()));
    let two = get(&mut m, "/b", fresh.clone(), |_| {});
    assert_eq!(two.result, Ok(()));
    assert_eq!(fresh.received(), request_of("/b"));
    let text = two.seen.text();
    assert!(
        text.iter()
            .any(|l| l.ends_with("seems to be dead, terminating\n")),
        "{text:?}"
    );
    assert_eq!(
        text.last().unwrap(),
        &format!("Connection #1 to host 127.0.0.1:{PORT} left intact\n")
    );
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
struct Watched(Arc<Mutex<Vec<WatchedLine>>>);

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
        self.0.lock().unwrap().push(seen);
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
    let seen = watched.0.lock().unwrap();
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
        ids.push(m.add(Box::new(e), (), &mut NoEvents).unwrap());
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
                crate::options::UploadSource::Bytes(curl_alloc::TryArc::try_new(body).unwrap());
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
        o.upload = crate::options::UploadSource::Bytes(curl_alloc::TryArc::try_new(body).unwrap());
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
            .any(|l| l.starts_with("Done waiting") || l.starts_with("Keep sending"))
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
    // Only a body larger than 1 MiB has it added.
    let mib = vec![b'x'; 1024 * 1024];
    let (at_most, _) = expecting(OK_EMPTY, &mib, |_| {});
    let head =
        String::from_utf8_lossy(&at_most.request[..at_most.request.len() - mib.len()]).into_owned();
    assert!(!head.contains("Expect"), "{head}");
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

/// A final response that ends before any 100, on a connection that
/// closes, stops the body unsent rather than wait for the 100 and send it
/// to a server that may have closed: said when the response's end is read
/// and the connection is to close, silently but for the abort when the
/// connection's end is the response's.
#[test]
fn a_response_ending_on_a_closing_connection_stops_the_body() {
    let asked = |o: &mut Options| {
        o.http.headers = UserHeaders::new([&b"Expect: 100-continue"[..]]).unwrap();
    };
    let closing = b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\nConnection: close\r\n\r\nok\n";
    let (ran, waited) = expecting(closing, b"a=b", asked);
    assert_eq!((ran.result, waited), (Ok(()), Duration::ZERO));
    assert!(ran.request.ends_with(b"\r\n\r\n"), "the head alone");
    assert_eq!(ran.easy.report().sizes().upload(), 0);
    let text = ran.seen.text();
    let stop = text
        .iter()
        .position(|l| l == "we are done reading and this is set to close, stop send\n");
    let abort = text.iter().position(|l| l == "abort upload\n");
    assert!(stop.is_some() && abort == stop.map(|at| at + 1), "{text:?}");
    assert!(
        !text.iter().any(|l| l.starts_with("Done waiting")),
        "{text:?}"
    );

    let (mut m, talk, clock) = server(&[b"HTTP/1.1 200 OK\r\n\r\nok\n"], true);
    let start = clock.now();
    let until_close = get(&mut m, "/p", talk, |o| {
        o.method = Method::Post;
        o.upload = crate::options::UploadSource::Bytes(
            curl_alloc::TryArc::try_new(b"a=b".to_vec()).unwrap(),
        );
        asked(o);
    });
    assert_eq!(until_close.result, Ok(()));
    assert_eq!(clock.now(), start, "no wait for the 100");
    assert!(until_close.request.ends_with(b"\r\n\r\n"), "the head alone");
    assert_eq!(until_close.seen.body(), b"ok\n");
    let text = until_close.seen.text();
    assert!(text.contains(&"abort upload\n".to_string()), "{text:?}");
    assert!(
        !text
            .iter()
            .any(|l| l.starts_with("we are done reading") || l.starts_with("Done waiting")),
        "{text:?}"
    );
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
    let heads = ran.seen.of("out");
    assert!(
        heads.iter().all(|h| !h.is_empty()),
        "the head traced once, no empty part of it after"
    );
}

/// The upload buffer is the size the application set
/// (`CURLOPT_UPLOAD_BUFFERSIZE`): the head shares the first, and each
/// after it is that size.
#[test]
fn the_upload_buffer_is_the_size_set() {
    use crate::options::UploadBufferSize;
    let body: Vec<u8> = (0..100_000u32).map(|i| (i % 251) as u8).collect();
    let ran = with_body(Method::Upload, &body, |o| {
        o.limits.upload_buffer = UploadBufferSize::clamped(16411);
    });
    assert_eq!(ran.result, Ok(()));
    let head_len = ran.request.len() - body.len();
    let pieces = ran.seen.of("dataout");
    assert_eq!(pieces.concat(), body);
    assert_eq!(pieces[0].len(), 16411 - head_len, "behind the head");
    assert_eq!(pieces[1].len(), 16411);
}

/// The application's method replaces the word on the request line; the
/// body is still the one the method implies.
#[test]
fn a_custom_method_is_sent_with_the_body_kept() {
    let ran = with_body(Method::Post, b"a=b", |o| {
        o.http.custom.make_mut().unwrap().method = Some(b"PATCH".to_vec());
    });
    assert_eq!(ran.result, Ok(()));
    assert!(ran.request.starts_with(b"PATCH /p HTTP/1.1\r\n"));
    assert!(ran.request.ends_with(b"x-www-form-urlencoded\r\n\r\na=b"));
}

/// The application's target replaces the request line's, and nothing
/// else: Digest still answers for the URL's path (`http_target`).
#[test]
fn a_request_target_replaces_only_the_request_line_s() {
    let (mut m, talk, _) = server(&[DIGEST_CHALLENGE, OK], false);
    let ran = get(&mut m, "/a?q", talk, |o| {
        o.http.custom.make_mut().unwrap().target = Some(b"*".to_vec());
        *o.login.make_mut().unwrap() = crate::options::Login::from_pair(b"u:p").unwrap();
        o.http.auth = crate::options::HttpAuth(AuthMethods::DIGEST);
    });
    assert_eq!(ran.result, Ok(()));
    let text = String::from_utf8_lossy(&ran.request).into_owned();
    assert!(text.starts_with("GET * HTTP/1.1\r\n"), "{text}");
    let second = text.rfind("GET ").unwrap();
    assert!(text[second..].starts_with("GET * HTTP/1.1\r\n"), "{text}");
    assert!(text[second..].contains(", uri=\"/a?q\", "), "{text}");
}

/// A body read in these pieces, of unknown size.
fn pieces(pieces: &[&[u8]]) -> crate::options::UploadSource {
    struct Pieces(Mutex<Vec<Vec<u8>>>);
    impl crate::handler::ReadHandler for Pieces {
        fn read(&self, _: &mut TransferCx<'_>, buf: &mut [u8]) -> crate::handler::Read {
            let mut left = self.0.lock().unwrap();
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
        handler: Handler::read(Pieces(Mutex::new(left))).unwrap(),
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

/// The application's lines, which it may add to at any time.
#[derive(Clone, Default)]
struct Appendable(Arc<Mutex<Vec<Vec<u8>>>>);

impl crate::handler::LineSource for Appendable {
    fn lines(
        &self,
        line: &mut dyn FnMut(&[u8]) -> Result<(), curl_alloc::OutOfMemory>,
    ) -> Result<(), curl_alloc::OutOfMemory> {
        self.0.lock().unwrap().iter().try_for_each(|l| line(l))
    }
}

/// Adds a line to the application's list as the connection is first
/// tried: after the transfer and its request started, before the request
/// is built.
struct AppendsOnTrying(Appendable, &'static [u8]);

impl DebugHandler for AppendsOnTrying {
    fn debug(&self, _: &mut TransferCx<'_>, kind: DebugKind, data: &[u8]) {
        if kind == DebugKind::Text && data.starts_with(b"  Trying") {
            self.0.0.lock().unwrap().push(self.1.to_vec());
        }
    }
}

/// A POST read from a handler, asked chunked by a header line the
/// application adds after the transfer started, goes chunked and is read
/// to its end whatever size it was given; an upload keeps its size. C
/// reads the list and decides as it builds the request (`set_reader`,
/// `http_req_set_TE`); the C build sends all 20 bytes.
#[test]
fn a_post_asked_chunked_as_its_request_is_built_reads_to_the_end() {
    for (method, sent) in [
        (Method::Post, "14\r\n0123456789abcdefghij\r\n0\r\n\r\n"),
        (Method::Upload, "5\r\n01234\r\n0\r\n\r\n"),
    ] {
        let list = Appendable::default();
        list.0.lock().unwrap().push(b"Expect:".to_vec());
        let stream = Stream::new(b"0123456789abcdefghij");
        let ran = with_body(method, b"", |o| {
            o.upload = match stream.source(false) {
                UploadSource::Read {
                    handler, rewind, ..
                } => UploadSource::Read {
                    handler,
                    rewind,
                    size: Some(5),
                },
                _ => unreachable!(),
            };
            o.http.headers =
                UserHeaders::from_source(Handler::lines(list.clone()).unwrap()).unwrap();
            let appends = AppendsOnTrying(list.clone(), b"Transfer-Encoding: chunked");
            o.callbacks.debug = Some(Handler::debug(appends).unwrap());
        });
        assert_eq!(ran.result, Ok(()));
        let request = String::from_utf8(ran.request).unwrap();
        assert!(
            request.contains("\r\nTransfer-Encoding: chunked\r\n")
                && !request.contains("Content-Length")
                && request.ends_with(&format!("\r\n\r\n{sent}")),
            "{method:?}: {request}"
        );
    }
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

/// A redirect reaches only the schemes the application lets it, HTTP's
/// among them only if it says so.
#[test]
fn a_redirect_goes_only_where_the_option_lets_it() {
    let defaults = Schemes::NONE.redirect;
    for scheme in [&b"http"[..], b"https", b"ftp", b"ftps"] {
        assert!(defaults.contains(scheme));
    }
    assert!(!defaults.contains(b"file") && !defaults.contains(b"nonsense"));
    assert_eq!(Protocols::of(&["http", "nonsense"]), None);
    let ran = run("/a", &moved("/b", false), false, |o| {
        o.http.follow = Follow::All;
        o.schemes.make_mut().unwrap().redirect = Protocols::of(&["ftp"]).unwrap();
    });
    assert_eq!(ran.result, Err(ErrorKind::UnsupportedProtocol));
    let text = ran.seen.text();
    assert!(
        text.contains(&"Protocol \"http\" is disabled (in redirect)\n".to_string()),
        "{text:?}"
    );
}

/// A URL reaches only the schemes the application allows, the first as
/// much as one a redirect leads to; a redirect needs both lists.
#[test]
fn a_url_goes_only_where_the_option_lets_it() {
    let http = Protocols::of(&["http"]).unwrap();
    let ftp = Protocols::of(&["ftp"]).unwrap();
    // The first URL is refused, before anything is sent.
    let ran = run("/a", OK, false, |o| {
        o.schemes.make_mut().unwrap().allowed = ftp;
    });
    assert_eq!(ran.result, Err(ErrorKind::UnsupportedProtocol));
    let text = ran.seen.text();
    assert!(
        text.contains(&"Protocol \"http\" is disabled\n".to_string()),
        "{text:?}"
    );
    // Allowed, the first goes, and a redirect allowed there too.
    let (mut m, talk, _) = server(&[&moved("/b", false), OK], false);
    let ran = get(&mut m, "/a", talk, |o| {
        o.http.follow = Follow::All;
        o.schemes.make_mut().unwrap().allowed = http;
    });
    assert_eq!(ran.result, Ok(()));
    assert_eq!(ran.seen.body(), b"ok\n");
    // A redirect the redirect list allows is refused if the other does
    // not.
    let ran = run("/a", &moved("/b", false), false, |o| {
        o.http.follow = Follow::All;
        let schemes = o.schemes.make_mut().unwrap();
        schemes.allowed = ftp.union(http);
        schemes.redirect = ftp;
    });
    assert_eq!(ran.result, Err(ErrorKind::UnsupportedProtocol));
    // None allowed refuses any URL.
    assert!(Protocols::NONE.is_empty() && !http.is_empty());
    let ran = run("/a", OK, false, |o| {
        o.schemes.make_mut().unwrap().allowed = Protocols::NONE;
    });
    assert_eq!(ran.result, Err(ErrorKind::UnsupportedProtocol));
}

/// The schemes this build speaks are named in any case; one it leaves
/// out, or no scheme at all, is not.
#[test]
fn built_schemes_are_named_in_any_case() {
    let http = Protocols::of(&["http"]).unwrap();
    assert_eq!(Protocols::built(b"http"), Some(http));
    assert_eq!(Protocols::built(b"HtTp"), Some(http));
    assert_eq!(Protocols::built(b"FILE"), Protocols::of(&["file"]));
    for name in [
        &b"https"[..],
        b"ftp",
        b"goobar",
        b"http ",
        b"",
        b"h",
        b"telnetx",
    ] {
        assert_eq!(Protocols::built(name), None, "{name:?}");
    }
    assert_eq!(http.union(Protocols::NONE), http);
    let ftp = Protocols::of(&["ftp"]).unwrap();
    assert_eq!(http.union(http), http, "a scheme in both is in either");
    assert!(http.union(ftp).contains(b"http") && http.union(ftp).contains(b"ftp"));
    assert!(Protocols::ALL.contains(b"gopher") && !Protocols::ALL.contains(b"nonsense"));
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
            *o.login.make_mut().unwrap() =
                crate::options::Login::from_pair(b"smith:doggie").unwrap();
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
            *o.login.make_mut().unwrap() = crate::options::Login::from_pair(b"u:p").unwrap();
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
        *o.login.make_mut().unwrap() = crate::options::Login::from_pair(b"u:p").unwrap();
        o.http.auth = crate::options::HttpAuth(AuthMethods::ANY);
    });
    assert_eq!(ran.result, Ok(()));
    let mut easy = ran.easy;
    for (want, sent) in [(AuthMethods::ANY, true), (AuthMethods::DIGEST, false)] {
        let (mut m, talk, _) = server(&[OK], false);
        easy.options_mut().http.auth = crate::options::HttpAuth(want);
        let id = m.add(Box::new(easy), (), &mut NoEvents).unwrap();
        let result = drive_to_completion(&mut m, id, &mut NoEvents).unwrap();
        assert_eq!(result, Ok(()));
        easy = *m.remove(id, &mut NoEvents).unwrap().easy;
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
        o.upload = UploadSource::Bytes(curl_alloc::TryArc::try_new(b"a=b".to_vec()).unwrap());
        o.http.headers = UserHeaders::new([&b"Content-Length: 3"[..]]).unwrap();
        *o.login.make_mut().unwrap() = crate::options::Login::from_pair(b"u:p").unwrap();
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
        o.upload = UploadSource::Bytes(curl_alloc::TryArc::try_new(b"a=b".to_vec()).unwrap());
        *o.login.make_mut().unwrap() = crate::options::Login::from_pair(b"u:p").unwrap();
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
        *o.login.make_mut().unwrap() = crate::options::Login::from_pair(b"u:p").unwrap();
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
        *o.login.make_mut().unwrap() = crate::options::Login::from_pair(b"u:p").unwrap();
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
        *o.login.make_mut().unwrap() = crate::options::Login::from_pair(b"u:p").unwrap();
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
            o.login.make_mut().unwrap().bearer = Some(b"mF_9.B5f".to_vec());
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
            o.netrc.make_mut().unwrap().mode = mode;
            o.netrc.make_mut().unwrap().file = Some(file.clone());
            if let Some(pair) = login {
                *o.login.make_mut().unwrap() = crate::options::Login::from_pair(pair).unwrap();
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
                *o.login.make_mut().unwrap() = crate::options::Login::from_pair(b"u:p").unwrap();
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
        o.upload = UploadSource::Bytes(curl_alloc::TryArc::try_new(body).unwrap());
        o.http.follow = Follow::All;
        set(o);
    })
}

/// A body the handle holds, sent and then redirected, is said to need a
/// rewind for the next request, before the next request is issued: the
/// C build says so for `-d` and COPYPOSTFIELDS (`cr_buf`), whatever
/// method follows.
#[test]
fn a_redirected_body_of_bytes_needs_a_rewind() {
    for code in [302, 307] {
        let ran = redirected(code, Method::Post, b"a=b", |_| {});
        assert_eq!(ran.result, Ok(()));
        let text = ran.seen.text();
        let need = text
            .iter()
            .position(|l| l == "Need to rewind upload for next request\n");
        let issue = text
            .iter()
            .position(|l| l.starts_with("Issue another request"));
        assert!(need.is_some() && need < issue, "{code}: {text:?}");
        assert_eq!(
            text.iter()
                .filter(|l| l.starts_with("Need to rewind"))
                .count(),
            1
        );
    }
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
    let custom =
        |o: &mut Options| o.http.custom.make_mut().unwrap().method = Some(b"DELETE".to_vec());
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

/// A debug handler that changes the transfer's options when a line
/// starting with `at` is traced, as an application's may.
struct ChangesOn {
    at: &'static [u8],
    change: Box<dyn Fn(&mut Options) + Send + Sync>,
}

impl DebugHandler for ChangesOn {
    fn debug(&self, cx: &mut TransferCx<'_>, kind: DebugKind, data: &[u8]) {
        if kind == DebugKind::Text && data.starts_with(self.at) {
            let me = cx.me();
            (self.change)(cx.options_mut(me).expect("its own transfer"));
        }
    }
}

/// A custom method the debug handler sets while the switch to GET is
/// traced is the next request's, as C's `http_switch_to_get` leaves it.
#[test]
fn a_custom_method_set_while_a_redirect_is_traced_stands() {
    let ran = redirected(303, Method::Get, b"", |o| {
        o.http.custom.make_mut().unwrap().method = Some(b"DELETE".to_vec());
        let change = ChangesOn {
            at: b"Stick to DELETE instead of GET",
            change: Box::new(|o| {
                o.http.custom.make_mut().unwrap().method = Some(b"PATCH".to_vec())
            }),
        };
        o.callbacks.debug = Some(Handler::debug(change).unwrap());
    });
    assert_eq!(ran.result, Ok(()));
    let second = second_request(&ran);
    assert!(second.starts_with("PATCH /b "), "{second}");
}

/// The resolve and connect-to lists stay in the options while their
/// entries are traced: what the debug handler sets them to then stands.
#[test]
fn lists_set_while_their_entries_are_traced_stand() {
    let lines = |l: &crate::options::Lines| l.iter().map(<[u8]>::to_vec).collect::<Vec<_>>();
    let entry = format!("127.0.0.1:{PORT}:127.0.0.1");
    let ran = run("/", OK, false, |o| {
        o.resolve.set([entry.as_bytes()]).unwrap();
        let change = ChangesOn {
            at: b"[DNS] added 127.0.0.1",
            change: Box::new(|o| o.resolve.set([&b"set.test:1:127.0.0.1"[..]]).unwrap()),
        };
        o.callbacks.debug = Some(Handler::debug(change).unwrap());
    });
    assert_eq!(ran.result, Ok(()));
    let resolve: Vec<_> = ran.easy.options().resolve.entries().collect();
    assert_eq!(resolve, [b"set.test:1:127.0.0.1"]);

    let ran = run("/", OK, false, |o| {
        o.connect_to.set([&b"::localhost:x"[..]]).unwrap();
        let change = ChangesOn {
            at: b"No valid port number",
            change: Box::new(|o| o.connect_to.set([&b"::127.0.0.1:1"[..]]).unwrap()),
        };
        o.callbacks.debug = Some(Handler::debug(change).unwrap());
    });
    assert_eq!(ran.result, Err(ErrorKind::SetoptOptionSyntax));
    assert_eq!(lines(&ran.easy.options().connect_to), [b"::127.0.0.1:1"]);
}

/// A resolve list set while the one before it is read is done with too:
/// the next transfer does not read it, as C clears `state.resolve` once
/// it has read the old list (`Curl_loadhostpairs`). The C build fails
/// the next transfer to a name only the new list gives.
#[test]
fn a_resolve_list_set_while_one_is_read_is_dropped() {
    let entry = format!("127.0.0.1:{PORT}:127.0.0.1");
    let later = format!("set.test:{PORT}:127.0.0.1");
    let (mut m, talk, _) = server(&[OK, OK], false);
    let first = get(&mut m, "/", talk.clone(), |o| {
        o.resolve.set([entry.as_bytes()]).unwrap();
        let later = later.clone();
        let change = ChangesOn {
            at: b"[DNS] added 127.0.0.1",
            change: Box::new(move |o| o.resolve.set([later.as_bytes()]).unwrap()),
        };
        o.callbacks.debug = Some(Handler::debug(change).unwrap());
    });
    assert_eq!(first.result, Ok(()));
    let ran = get_with(&mut m, first.easy, "/", talk, |o| {
        let url = format!("http://set.test:{PORT}/");
        o.set_url(Some(url.as_bytes())).unwrap();
    });
    assert_eq!(ran.result, Err(ErrorKind::CouldntResolveHost));
}

/// A body read from a handler, `data`, started over by its rewind
/// handler if it has one; counts its rewinds.
#[derive(Clone)]
struct Stream {
    data: &'static [u8],
    at: Arc<crate::test_cell::Cell<usize>>,
    rewinds: Arc<crate::test_cell::Cell<u32>>,
}

impl Stream {
    fn new(data: &'static [u8]) -> Stream {
        Stream {
            data,
            at: Arc::default(),
            rewinds: Arc::default(),
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

/// A body of `n` bytes, kept for the test's run.
fn big_body(n: usize) -> &'static [u8] {
    Box::leak(vec![b'a'; n].into_boxed_slice())
}

/// The bytes after the first head in `bytes`.
fn after_head(bytes: &[u8]) -> usize {
    let at = bytes
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .expect("a head");
    bytes.len() - at - 4
}

/// A redirect read while the body goes, much of it left: the connection
/// closes rather than carry the rest, after the one buffer sent with the
/// head, and the body goes whole on a new one (`http_perhapsrewind`).
#[test]
fn a_redirect_mid_body_closes_rather_than_send_the_rest() {
    const SIZE: usize = 300_000;
    let first = Conversation::replies(&[&redirect(307, "/b")], false);
    let second = Conversation::replies(&[OK], false);
    let mut m = serving(Peer::Accepts, &[&first, &second]);
    let stream = Stream::new(big_body(SIZE));
    let ran = get(&mut m, "/a", first.clone(), |o| {
        o.method = Method::Upload;
        o.upload = stream.source(true);
        o.http.follow = Follow::All;
    });
    assert_eq!(ran.result, Ok(()));
    // The head and the body read behind it fill one buffer; the redirect
    // is heard before another goes.
    let sent = first.received();
    assert_eq!(sent.len(), 65536);
    let left = SIZE - after_head(&sent);
    let text = ran.seen.text();
    let close = format!("close instead of sending {left} more bytes\n");
    let need = text
        .iter()
        .position(|l| l == "Need to rewind upload for next request\n");
    let at = text.iter().position(|l| *l == close);
    let keep = text
        .iter()
        .position(|l| l == "Keep sending data to get tossed away\n");
    assert!(need < at && at < keep && need.is_some(), "{text:?}");
    assert!(
        !text.iter().any(|l| l.starts_with("abort upload")),
        "{text:?}"
    );
    assert_eq!(after_head(&second.received()), SIZE);
    assert_eq!(stream.rewinds.get(), 1);
    assert_eq!(ran.easy.report().connects(), 2);
}

/// Each pass reads at most one more buffer of the body, so the response
/// is heard between buffers (`Curl_req_send_more`): a server that never
/// answers is sent a buffer a perform.
#[test]
fn a_pass_sends_one_buffer_of_the_body() {
    const SIZE: usize = 300_000;
    let (mut m, talk, _) = server(&[], false);
    let mut e = Easy::new();
    let url = format!("http://127.0.0.1:{PORT}/a");
    let stream = Stream::new(big_body(SIZE));
    let o = e.options_mut();
    o.set_url(Some(url.as_bytes())).unwrap();
    o.method = Method::Upload;
    o.upload = stream.source(true);
    let _id = m.add(Box::new(e), (), &mut NoEvents).unwrap();
    // The connect started in the first pass is taken in the next.
    m.perform(&mut NoEvents).unwrap();
    let body = |r: &[u8]| {
        r.windows(4)
            .position(|w| w == b"\r\n\r\n")
            .map_or(0, |at| r.len() - at - 4)
    };
    let mut performs = 0;
    while body(&talk.received()) < SIZE {
        assert!(performs < 100, "the body does not go");
        m.perform(&mut NoEvents).unwrap();
        performs += 1;
        // The first perform sends the head's buffer, and a pass's.
        let now = talk.received().len();
        assert!(
            now <= 65536 * (performs + 1),
            "{now} bytes after {performs} performs"
        );
        assert!(
            now > 65536 * performs.min(SIZE / 65536),
            "{now} bytes after {performs} performs: a pass sends what it read"
        );
    }
    assert!(performs >= SIZE / 65536, "{performs} performs");
}

/// With little of the body left, it goes to be dropped, the response's
/// body is ignored, and the connection serves the next request.
#[test]
fn a_redirect_with_little_of_the_body_left_keeps_the_connection() {
    // One buffer and 500 bytes more: what the head takes of the buffer
    // is left too, still under 2000.
    let size = 65536 + 500;
    let talk = Conversation::replies(&[&redirect(307, "/b"), OK], false);
    let mut m = serving(Peer::Accepts, &[&talk]);
    let stream = Stream::new(big_body(size));
    let ran = get(&mut m, "/a", talk.clone(), |o| {
        o.method = Method::Upload;
        o.upload = stream.source(true);
        o.http.follow = Follow::All;
    });
    assert_eq!(ran.result, Ok(()));
    let text = ran.seen.text();
    assert!(
        text.contains(&"Keep sending data to get tossed away\n".to_string()),
        "{text:?}"
    );
    assert!(
        !text.iter().any(|l| l.starts_with("close instead")),
        "{text:?}"
    );
    assert!(
        !text.iter().any(|l| l.contains("before end of send")),
        "{text:?}"
    );
    assert_eq!(ran.easy.report().connects(), 1);
    let head = ran
        .request
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .unwrap()
        + 4;
    let left = size - (65536 - head);
    assert!(left < 2000, "{left} left after the first buffer");
    assert!(second_request(&ran).ends_with(&"a".repeat(size)));
}

/// A 401 read while the body goes is answered on a new connection: the
/// first closes rather than carry the rest of the body.
#[test]
fn a_challenge_mid_body_closes_rather_than_send_the_rest() {
    let first = Conversation::replies(&[DIGEST_CHALLENGE], false);
    let second = Conversation::replies(&[OK], false);
    let mut m = serving(Peer::Accepts, &[&first, &second]);
    let stream = Stream::new(big_body(300_000));
    let ran = get(&mut m, "/a", first.clone(), |o| {
        o.method = Method::Upload;
        o.upload = stream.source(true);
        *o.login.make_mut().unwrap() = crate::options::Login::from_pair(b"u:p").unwrap();
        o.http.auth = crate::options::HttpAuth(AuthMethods::ANY);
    });
    assert_eq!(ran.result, Ok(()));
    assert_eq!(first.received().len(), 65536);
    let text = ran.seen.text();
    assert!(
        text.iter()
            .any(|l| l.starts_with("close instead of sending ")),
        "{text:?}"
    );
    assert!(fixture::find(&second.received(), b"Authorization: Digest").is_some());
    assert_eq!(after_head(&second.received()), 300_000);
    assert_eq!(ran.easy.report().connects(), 2);
}

/// A body of unknown size is never little enough to keep the connection.
#[test]
fn a_redirect_mid_body_of_unknown_size_closes() {
    let first = Conversation::replies(&[&redirect(307, "/b")], false);
    let second = Conversation::replies(&[OK], false);
    let mut m = serving(Peer::Accepts, &[&first, &second]);
    let stream = Stream::new(big_body(300_000));
    let ran = get(&mut m, "/a", first.clone(), |o| {
        o.method = Method::Upload;
        o.upload = match stream.source(true) {
            UploadSource::Read {
                handler, rewind, ..
            } => UploadSource::Read {
                handler,
                rewind,
                size: None,
            },
            _ => unreachable!(),
        };
        o.http.follow = Follow::All;
    });
    assert_eq!(ran.result, Ok(()));
    let text = ran.seen.text();
    let close = "close instead of sending unknown amount of more bytes\n".to_string();
    assert!(text.contains(&close), "{text:?}");
    assert_eq!(ran.easy.report().connects(), 2);
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
            o.http.custom.make_mut().unwrap().referer = Some(b"given".to_vec());
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
    // The 417 comes while the body waits for a 100, not before the wait
    // starts.
    let (mut m, talk, _) = server(&[refused, OK], false);
    let talk = talk.late_replies();
    let body = vec![b'x'; 2 * 1024 * 1024];
    let ran = get(&mut m, "/a", talk, |o| {
        o.method = Method::Upload;
        o.upload = UploadSource::Bytes(curl_alloc::TryArc::try_new(body).unwrap());
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

/// The request a 417 has made again goes to its URL as given, the
/// application's port dropped: C follows the request's own URL, which
/// never carried that port, as a redirect to an absolute URL
/// (`Curl_http_follow`'s `disallowport`). The C build tries port 1.
#[test]
fn a_417_retry_drops_the_application_s_port() {
    let refused: &[u8] = b"HTTP/1.1 417 Expectation Failed\r\nContent-Length: 0\r\n\r\n";
    let (mut m, talk, _) = server(&[refused, OK], false);
    let ran = get(&mut m, "/a", talk, |o| {
        o.set_url(Some(b"http://127.0.0.1:1/a")).unwrap();
        o.port = std::num::NonZeroU16::new(PORT);
        o.method = Method::Post;
        o.upload = UploadSource::Bytes(curl_alloc::TryArc::try_new(b"hello".to_vec()).unwrap());
        o.http.headers = UserHeaders::new([&b"Expect: 100-continue"[..]]).unwrap();
    });
    assert_eq!(ran.result, Err(ErrorKind::CouldntConnect));
    let said = ran.seen.text();
    let issue = "Issue another request to this URL: 'http://127.0.0.1:1/a'\n".to_string();
    assert!(said.contains(&issue), "{said:?}");
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

/// The request line carries the path percent-encoded, its lowercase hex
/// made uppercase, and the query as it was given (`url.c` reads the path
/// with `CURLU_URLENCODE`, the query without).
#[test]
fn the_path_is_sent_encoded_and_the_query_as_given() {
    let (mut m, talk, _) = server(&[OK], false);
    let ran = get(&mut m, "/é/%c3%a9?q=é&%c3%a9", talk, |_| {});
    assert_eq!(ran.result, Ok(()));
    let line = "GET /%C3%A9/%C3%A9?q=é&%c3%a9 HTTP/1.1\r\n";
    assert!(ran.request.starts_with(line.as_bytes()));
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

/// The application's port goes where the request goes, not into the URL
/// a 401's retry traces, the report keeps and a referer names: the C
/// build traces `'http://127.0.0.1:1/a'` there, its `state.url` read back
/// before `Curl_peer_from_url` sets the port in `state.uh`.
#[test]
fn a_401_retry_names_the_url_without_the_application_s_port() {
    let (mut m, talk, _) = server(&[CHALLENGE, OK], false);
    let ran = get(&mut m, "/a", talk, |o| {
        o.set_url(Some(b"http://127.0.0.1:1/a")).unwrap();
        o.port = std::num::NonZeroU16::new(PORT);
        *o.login.make_mut().unwrap() = crate::options::Login::from_pair(b"u:p").unwrap();
        o.http.auth = crate::options::HttpAuth(AuthMethods::ANY);
        o.http.auto_referer = true;
    });
    assert_eq!(ran.result, Ok(()));
    let said = "Issue another request to this URL: 'http://127.0.0.1:1/a'\n".to_string();
    assert!(ran.seen.text().contains(&said), "{:?}", ran.seen.text());
    assert_eq!(ran.easy.report().url().unwrap(), b"http://127.0.0.1:1/a");
    let text = String::from_utf8_lossy(&ran.request);
    let second = &text[text.rfind("GET /a ").unwrap()..];
    assert!(
        second.contains(&format!("\r\nHost: 127.0.0.1:{PORT}\r\n"))
            && second.contains("\r\nReferer: http://127.0.0.1:1/a\r\n"),
        "{second}"
    );
}

/// A relative redirect resolves against the URL with the application's
/// port applied (C's `state.uh`), both followed and kept: the C build
/// traces and reports the applied port there, and sends the first
/// request's own URL as the referer.
#[test]
fn a_relative_redirect_resolves_with_the_application_s_port() {
    let (mut m, talk, _) = server(&[&redirect(302, "/b"), OK], false);
    let ran = get(&mut m, "/a", talk, |o| {
        o.set_url(Some(b"http://127.0.0.1:1/a")).unwrap();
        o.port = std::num::NonZeroU16::new(PORT);
        o.http.follow = Follow::All;
        o.http.auto_referer = true;
    });
    assert_eq!(ran.result, Ok(()));
    let said = format!("Issue another request to this URL: 'http://127.0.0.1:{PORT}/b'\n");
    assert!(ran.seen.text().contains(&said), "{:?}", ran.seen.text());
    let second = second_request(&ran);
    assert!(
        second.contains("\r\nReferer: http://127.0.0.1:1/a\r\n"),
        "{second}"
    );
    assert_eq!(
        ran.easy.report().url().unwrap(),
        format!("http://127.0.0.1:{PORT}/b").as_bytes()
    );

    let (mut m, talk, _) = server(&[&redirect(302, "/b")], false);
    let ran = get(&mut m, "/a", talk, |o| {
        o.set_url(Some(b"http://127.0.0.1:1/a")).unwrap();
        o.port = std::num::NonZeroU16::new(PORT);
    });
    assert_eq!(ran.result, Ok(()));
    assert_eq!(ran.easy.report().url().unwrap(), b"http://127.0.0.1:1/a");
    let kept = format!("http://127.0.0.1:{PORT}/b");
    assert_eq!(ran.easy.report().redirect_url(), Some(kept.as_bytes()));
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
        o.http.cookies.make_mut().unwrap().files.push(b"").unwrap();
        o.http.cookies.make_mut().unwrap().send = Some(b"app=2".to_vec());
    });
    assert_eq!(ran.result, Ok(()));
    let text = String::from_utf8_lossy(&ran.request).into_owned();
    let (first, second) = text.split_at(text.find("GET /b ").unwrap());
    assert!(first.contains("\r\nCookie: app=2\r\n"), "{first}");
    assert!(second.contains("\r\nCookie: a=1; app=2\r\n"), "{second}");
    let seen = ran.seen.0.lock().unwrap();
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
        o.http.cookies.make_mut().unwrap().files.push(b"").unwrap();
    });
    assert_eq!(ran.result, Ok(()));
    assert_eq!(
        ran.easy.cookie_list().unwrap(),
        [b"other.example\tFALSE\t/d\tFALSE\t0\ta\t1".to_vec()]
    );
}

/// A custom `Host:` that starts with a bracket names an address: what is
/// inside, or all after the bracket, its last byte twice, as C moves it.
#[test]
fn a_custom_host_in_brackets_names_the_cookies_host() {
    let reply = b"HTTP/1.1 200 OK\r\nSet-Cookie: a=1\r\nContent-Length: 0\r\n\r\n";
    for (host, domain) in [
        (&b"Host: [::1]:99"[..], &b"::1"[..]),
        (b"Host: [ab", b"abb"),
    ] {
        let (mut m, talk, _) = server(&[reply], false);
        let mut ran = get(&mut m, "/d/e", talk, |o| {
            o.http.headers = UserHeaders::new([host]).unwrap();
            o.http.cookies.make_mut().unwrap().files.push(b"").unwrap();
        });
        assert_eq!(ran.result, Ok(()));
        assert_eq!(
            ran.easy.cookie_list().unwrap(),
            [[domain, b"\tFALSE\t/d\tFALSE\t0\ta\t1"].concat()]
        );
    }
}

/// The cookie files are read as a transfer starts and their cookies sent;
/// one missing or a directory is warned of and passed over
/// (`Curl_cookie_loadfiles`).
#[test]
fn cookie_files_are_read_as_a_transfer_starts() {
    let dir = std::env::temp_dir().join(format!("curl-cookie-files-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let file = dir.join("jar");
    std::fs::write(&file, b"127.0.0.1\tFALSE\t/\tFALSE\t0\ta\t1\n").unwrap();
    let missing = dir.join("missing");
    let name = |p: &std::path::Path| p.as_os_str().as_encoded_bytes().to_vec();
    let ran = run("/", OK, false, |o| {
        for p in [&missing, &dir, &file] {
            o.http
                .cookies
                .make_mut()
                .unwrap()
                .files
                .push(&name(p))
                .unwrap();
        }
    });
    std::fs::remove_dir_all(&dir).unwrap();
    assert_eq!(ran.result, Ok(()));
    let request = String::from_utf8_lossy(&ran.request).into_owned();
    assert!(request.contains("\r\nCookie: a=1\r\n"), "{request}");
    let text = ran.seen.text().concat();
    for warning in [
        format!(
            "WARNING: failed to open cookie file \"{}\"\n",
            missing.display()
        ),
        format!(
            "WARNING: cookie filename points to a directory: \"{}\"\n",
            dir.display()
        ),
    ] {
        assert!(text.contains(&warning), "{text}");
    }
}

/// Each cookie file is read into the jar as it is reached: what its
/// lines say is traced before the next file is opened, between the
/// warnings of those that cannot be, as C's `cookie_load` traces them.
#[test]
fn cookie_files_are_read_in_turn_with_their_lines_traced() {
    let dir = std::env::temp_dir().join(format!("curl-cookie-turn-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let first = dir.join("first");
    std::fs::write(
        &first,
        b"Set-Cookie: =\n127.0.0.1\tFALSE\t/\tFALSE\t0\tok\t1\n",
    )
    .unwrap();
    let second = dir.join("second");
    std::fs::write(&second, b"Set-Cookie: two=2\nSet-Cookie: c\x01=1\n").unwrap();
    let missing = dir.join("missing");
    let name = |p: &std::path::Path| p.as_os_str().as_encoded_bytes().to_vec();
    let ran = run("/", OK, false, |o| {
        for p in [&first, &missing, &second] {
            o.http
                .cookies
                .make_mut()
                .unwrap()
                .files
                .push(&name(p))
                .unwrap();
        }
    });
    std::fs::remove_dir_all(&dir).unwrap();
    assert_eq!(ran.result, Ok(()));
    let text = ran.seen.text().concat();
    let said: Vec<&str> = text.lines().filter(|l| l.contains("cookie")).collect();
    let warning = format!(
        "WARNING: failed to open cookie file \"{}\"",
        missing.display()
    );
    assert_eq!(
        said,
        [
            "invalid cookie, dropped",
            &warning,
            "invalid octets in name, cookie dropped"
        ]
    );
}

/// A cookie file the debug handler names while a missing one is warned
/// of is read for the same transfer, as C walks the list it appends to.
#[test]
fn a_cookie_file_named_while_one_is_warned_of_is_read() {
    let dir = std::env::temp_dir().join(format!("curl-cookie-named-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let file = dir.join("jar");
    std::fs::write(&file, b"127.0.0.1\tFALSE\t/\tFALSE\t0\ta\t1\n").unwrap();
    let name = file.as_os_str().as_encoded_bytes().to_vec();
    let ran = run("/", OK, false, |o| {
        o.http
            .cookies
            .make_mut()
            .unwrap()
            .files
            .push(b"missing")
            .unwrap();
        let change = ChangesOn {
            at: b"WARNING: failed to open cookie file \"missing\"",
            change: Box::new(move |o| {
                o.http
                    .cookies
                    .make_mut()
                    .unwrap()
                    .files
                    .push(&name)
                    .unwrap()
            }),
        };
        o.callbacks.debug = Some(Handler::debug(change).unwrap());
    });
    std::fs::remove_dir_all(&dir).unwrap();
    assert_eq!(ran.result, Ok(()));
    let request = String::from_utf8_lossy(&ran.request).into_owned();
    assert!(request.contains("\r\nCookie: a=1\r\n"), "{request}");
    let files: Vec<_> = ran.easy.options().http.cookies.files.iter().collect();
    assert_eq!(files.len(), 2, "the file named stays named");
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
        o.http.cookies.make_mut().unwrap().files.push(b"").unwrap();
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

/// A request's count of stored `Set-Cookie:` lines (`req.setcookies`)
/// takes in the application's and a cookie file's, and starts again with
/// each request: as on the C build, a cookie file read with 50 counted
/// stores nothing, the application's lines after a response count with
/// its fields, and a file's 60 lines store 50 and leave the response its
/// own count.
#[test]
fn cookies_are_counted_with_the_request_s_as_c_counts_them() {
    let fields = |n: usize| {
        let mut reply = b"HTTP/1.1 200 OK\r\n".to_vec();
        for i in 0..n {
            reply.extend_from_slice(format!("Set-Cookie: s{i}=1\r\n").as_bytes());
        }
        reply.extend_from_slice(b"Content-Length: 0\r\n\r\n");
        reply
    };
    let add = |e: &mut Easy, n: usize, prefix: &str| {
        for i in 0..n {
            let line = format!("Set-Cookie: {prefix}{i}=1; domain=127.0.0.1");
            e.add_cookie(line.as_bytes(), |_| {}).unwrap();
        }
    };
    let netscape = |e: &mut Easy, name: &str| {
        let line = format!("127.0.0.1\tFALSE\t/\tFALSE\t0\t{name}\t1");
        e.add_cookie(line.as_bytes(), |_| {}).unwrap();
    };
    let dir = std::env::temp_dir().join(format!("curl-cookie-count-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let three = dir.join("three");
    let lines: String = (0..3)
        .map(|i| format!("127.0.0.1\tFALSE\t/\tFALSE\t0\tm{i}\t1\n"))
        .collect();
    std::fs::write(&three, lines).unwrap();
    let sixty = dir.join("sixty");
    let lines: String = (0..60)
        .map(|i| format!("Set-Cookie: f{i}=1; domain=127.0.0.1\n"))
        .collect();
    std::fs::write(&sixty, lines).unwrap();
    let name = |p: &std::path::Path| p.as_os_str().as_encoded_bytes().to_vec();
    let (ten, forty_five, none) = (fields(10), fields(45), fields(0));
    let (mut m, talk, _) = server(&[&ten, &forty_five, &none, &ten], false);

    let mut e = Easy::new();
    add(&mut e, 50, "a");
    let three = name(&three);
    let ran = get_with(&mut m, e, "/", talk.clone(), |o| {
        o.http
            .cookies
            .make_mut()
            .unwrap()
            .files
            .push(&three)
            .unwrap();
    });
    assert_eq!(ran.result, Ok(()));
    let mut e = ran.easy;
    assert_eq!(e.cookie_list().unwrap().len(), 60);
    add(&mut e, 5, "b");
    netscape(&mut e, "n9");
    assert_eq!(e.cookie_list().unwrap().len(), 66);

    let ran = get_with(&mut m, Easy::new(), "/", talk.clone(), |o| {
        o.http.cookies.make_mut().unwrap().files.push(b"").unwrap();
    });
    let mut e = ran.easy;
    add(&mut e, 10, "b");
    netscape(&mut e, "n1");
    assert_eq!(e.cookie_list().unwrap().len(), 50);
    let ran = get_with(&mut m, e, "/", talk.clone(), |_| {});
    let mut e = ran.easy;
    add(&mut e, 3, "c");
    assert_eq!(e.cookie_list().unwrap().len(), 53);

    let sixty = name(&sixty);
    let ran = get_with(&mut m, Easy::new(), "/", talk, |o| {
        o.http
            .cookies
            .make_mut()
            .unwrap()
            .files
            .push(&sixty)
            .unwrap();
    });
    let mut e = ran.easy;
    assert_eq!(e.cookie_list().unwrap().len(), 60);
    std::fs::remove_dir_all(&dir).unwrap();
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
    one.add_cookie(line, |_| {}).unwrap();
    assert!(two.cookie_list().unwrap().is_empty(), "each its own");
    // Kept from when no handle holds the share.
    one.set_share(None);
    two.set_share(None);
    share.keep(crate::share::Kind::Cookies).unwrap();
    one.set_share(Some(share.clone()));
    two.set_share(Some(share.clone()));
    one.add_cookie(line, |_| {}).unwrap();
    assert_eq!(two.cookie_list().unwrap(), [line.to_vec()]);
    // Saved only once a transfer started the jar; reading files does.
    let dir = std::env::temp_dir().join(format!("curl-share-jar-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let jar = dir.join("jar");
    two.options_mut().http.cookies.make_mut().unwrap().save_to =
        Some(jar.as_os_str().as_encoded_bytes().to_vec());
    two.save_cookies().unwrap();
    assert!(!jar.exists(), "no transfer started it");
    two.options_mut()
        .http
        .cookies
        .make_mut()
        .unwrap()
        .files
        .push(b"")
        .unwrap();
    two.reload_cookies(|_| {}).unwrap();
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

/// Handles on two threads store cookies in one share's jar at once, and
/// every one is there at the end.
#[test]
fn a_share_s_jar_takes_cookies_from_two_threads() {
    use crate::share::{Kind, Share};
    const EACH: usize = 20;
    let share = Share::new().unwrap();
    share.keep(Kind::Cookies).unwrap();
    std::thread::scope(|scope| {
        for t in 0..2 {
            let share = share.clone();
            scope.spawn(move || {
                let mut e = Easy::new();
                e.set_share(Some(share));
                for i in 0..EACH {
                    let line = format!("example.com\tFALSE\t/\tFALSE\t0\tt{t}_{i}\t1");
                    e.add_cookie(line.as_bytes(), |_| {}).unwrap();
                }
            });
        }
    });
    let mut e = Easy::new();
    e.set_share(Some(share));
    assert_eq!(e.cookie_list().unwrap().len(), 2 * EACH);
}

/// A transfer on a share that keeps names and cookies tells the
/// application of each use it makes of them, where C locks them (test
/// 506): the jar read and started, the name looked up, kept and let go,
/// the cookies the request sends and the one the server sets, the names
/// pruned at the end; then the jar at its flush.
#[test]
fn a_share_s_uses_are_told_where_c_locks_them() {
    use crate::share::{Kind, Told};
    let share = crate::share::Share::new().unwrap();
    share.keep(Kind::Names).unwrap();
    share.keep(Kind::Cookies).unwrap();
    let told = Told::new(&share);
    let (mut m, talk, _) = server(&[SETS_A_COOKIE], false);
    let mut e = Easy::new();
    e.set_share_watched(share.clone(), told.handler());
    let jar_on = |o: &mut Options| o.http.cookies.make_mut().unwrap().files.push(b"").unwrap();
    let mut ran = get_with(&mut m, e, "/a", talk, jar_on);
    assert_eq!(ran.result, Ok(()));
    let (c, n) = (Kind::Cookies, Kind::Names);
    assert_eq!(told.uses(), [c, c, n, n, n, c, c, n]);
    ran.easy.save_cookies().unwrap();
    assert_eq!(told.uses(), [c]);
}

/// Handles on a share that keeps cookies use its jar in whichever multi
/// runs them: what one transfer stores, the next sends.
#[test]
fn a_share_s_jar_serves_the_transfers_of_a_multi() {
    let share = crate::share::Share::new().unwrap();
    share.keep(crate::share::Kind::Cookies).unwrap();
    let jar_on = |o: &mut Options| o.http.cookies.make_mut().unwrap().files.push(b"").unwrap();
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
        o.proxy.make_mut().unwrap().url = Some(format!("127.0.0.1:{PORT}").into_bytes());
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

const PROXY_CHALLENGE: &[u8] = b"HTTP/1.1 407 Who\r\n\
    Proxy-Authenticate: Basic realm=\"p\"\r\nContent-Length: 0\r\n\r\n";

/// A proxy is given the options' credentials where its URL has none, once
/// its 407 picks a method from those wanted; they go before the origin's,
/// whose own go from the first request (`Curl_http_output_auth`).
#[test]
fn a_proxy_is_answered_with_its_own_credentials() {
    let (mut m, talk, _) = server(&[PROXY_CHALLENGE, OK], false);
    let ran = get(&mut m, "/", talk, |o| {
        o.set_url(Some(b"http://origin.example/a")).unwrap();
        o.proxy.make_mut().unwrap().url = Some(format!("127.0.0.1:{PORT}").into_bytes());
        o.proxy.make_mut().unwrap().user = Some(b"u".to_vec());
        o.proxy.make_mut().unwrap().password = Some(b"p".to_vec());
        o.proxy.make_mut().unwrap().auth = crate::options::HttpAuth(AuthMethods::ANY);
        *o.login.make_mut().unwrap() = crate::options::Login::from_pair(b"u2:p2").unwrap();
    });
    assert_eq!(ran.result, Ok(()));
    let text = String::from_utf8_lossy(&ran.request).into_owned();
    let request = |proxy: &str| {
        format!(
            "GET http://origin.example/a HTTP/1.1\r\nHost: origin.example\r\n{proxy}\
             Authorization: Basic dTI6cDI=\r\nUser-Agent: curl/test\r\nAccept: */*\r\n\
             Proxy-Connection: Keep-Alive\r\n\r\n"
        )
    };
    assert_eq!(
        text,
        request("") + &request("Proxy-Authorization: Basic dTpw\r\n")
    );
    let report = ran.easy.report();
    assert_eq!(report.proxy_auth_offered(), AuthMethods::BASIC);
    assert_eq!(report.proxy_auth_used(), AuthMethods::BASIC);
    assert_eq!(report.auth_offered(), AuthMethods::NONE);
    let said = ran.seen.text();
    let proxy = said
        .iter()
        .position(|l| l == "Proxy auth using Basic with user 'u'\n");
    let server = said
        .iter()
        .rposition(|l| l == "Server auth using Basic with user 'u2'\n");
    assert!(
        proxy.is_some_and(|p| server.is_some_and(|s| p < s)),
        "{said:?}"
    );
}

/// The application's own `Proxy-Authorization` is one of its headers, not
/// of the proxy's, and goes beside the one made for the proxy, as C sends
/// both.
#[test]
fn a_custom_proxy_authorization_goes_beside_the_proxy_s() {
    let (mut m, talk, _) = server(&[OK], false);
    let ran = get(&mut m, "/", talk, |o| {
        o.set_url(Some(b"http://origin.example/a")).unwrap();
        o.proxy.make_mut().unwrap().url = Some(format!("127.0.0.1:{PORT}").into_bytes());
        o.proxy.make_mut().unwrap().user = Some(b"u".to_vec());
        o.proxy.make_mut().unwrap().password = Some(b"p".to_vec());
        o.proxy.make_mut().unwrap().auth = crate::options::HttpAuth(AuthMethods::BASIC);
        o.http.headers = UserHeaders::new([&b"Proxy-Authorization: Mine"[..]]).unwrap();
    });
    assert_eq!(ran.result, Ok(()));
    let text = String::from_utf8_lossy(&ran.request).into_owned();
    assert!(
        text.contains("\r\nProxy-Authorization: Basic dTpw\r\n"),
        "{text}"
    );
    assert!(text.contains("\r\nProxy-Authorization: Mine\r\n"), "{text}");
}

/// The proxy's own `Proxy-Authorization` replaces the one the library
/// would make, and so does the application's for the origin where the
/// two are unified (`CURLOPT_HEADEROPT`), as C's `Curl_checkProxyheaders`
/// finds it.
#[test]
fn the_proxy_s_own_proxy_authorization_replaces_the_library_s() {
    for unified in [false, true] {
        let (mut m, talk, _) = server(&[OK], false);
        let ran = get(&mut m, "/", talk, |o| {
            o.set_url(Some(b"http://origin.example/a")).unwrap();
            o.proxy.make_mut().unwrap().url = Some(format!("127.0.0.1:{PORT}").into_bytes());
            o.proxy.make_mut().unwrap().user = Some(b"u".to_vec());
            o.proxy.make_mut().unwrap().password = Some(b"p".to_vec());
            o.proxy.make_mut().unwrap().auth = crate::options::HttpAuth(AuthMethods::BASIC);
            let mine = UserHeaders::new([&b"Proxy-Authorization: Mine"[..]]).unwrap();
            if unified {
                o.http.headers = mine;
                o.proxy.make_mut().unwrap().unified_headers = true;
            } else {
                o.proxy.make_mut().unwrap().headers = mine;
            }
        });
        assert_eq!(ran.result, Ok(()));
        let text = String::from_utf8_lossy(&ran.request).into_owned();
        assert!(!text.contains("Basic dTpw"), "{text}");
        let mine = text.matches("\r\nProxy-Authorization: Mine\r\n").count();
        assert_eq!(mine, 1, "{text}");
    }
}

/// A 407 from a host the request reached without a proxy's sending it
/// on is not the proxy's: its challenge is not read, and the proxy is
/// not answered with it later (test 1616).
#[test]
fn a_407_not_from_a_forwarding_proxy_is_not_the_proxy_s() {
    let attacker = b"HTTP/1.1 407 Who\r\n\
        Proxy-Authenticate: Digest realm=\"attacker\", nonce=\"1\"\r\nContent-Length: 0\r\n\r\n";
    let creds = |o: &mut Options| {
        o.proxy.make_mut().unwrap().user = Some(b"silly".to_vec());
        o.proxy.make_mut().unwrap().password = Some(b"person".to_vec());
        o.proxy.make_mut().unwrap().auth = crate::options::HttpAuth(AuthMethods::DIGEST);
    };
    let (mut m, talk, _) = server(&[attacker], false);
    let direct = get(&mut m, "/", talk, creds);
    assert_eq!(direct.result, Ok(()));
    assert_eq!(direct.easy.report().proxy_auth_offered(), AuthMethods::NONE);
    let (mut m, talk, _) = server(&[OK], false);
    let proxied = get_with(&mut m, direct.easy, "/", talk, |o| {
        creds(o);
        o.set_url(Some(b"http://origin.example/a")).unwrap();
        o.proxy.make_mut().unwrap().url = Some(format!("127.0.0.1:{PORT}").into_bytes());
    });
    assert_eq!(proxied.result, Ok(()));
    let text = String::from_utf8_lossy(&proxied.request).into_owned();
    assert!(!text.contains("Proxy-Authorization"), "{text}");
}

/// Through a SOCKS proxy: `kind`'s proxy at `PORT`, for the origin
/// `url`.
fn through_socks(o: &mut Options, kind: &str, url: &[u8]) {
    o.set_url(Some(url)).unwrap();
    o.proxy.make_mut().unwrap().url = Some(format!("{kind}://127.0.0.1:{PORT}").into_bytes());
}

const SOCKS5_GRANTED: &[u8] = b"\x05\x00\x00\x01\x7f\x00\x00\x01\x00\x50";

/// A SOCKS5 proxy that asks for the user and password is given them,
/// then the name to resolve; the request then goes as to the origin, and
/// the connection is traced as C traces it.
#[test]
fn a_socks5_proxy_logs_the_user_in_and_connects() {
    let talk =
        Conversation::replies(&[b"\x05\x02", b"\x01\x00", SOCKS5_GRANTED, OK], false).per_send();
    let mut m = serving(Peer::Accepts, &[&talk]);
    let ran = get(&mut m, "/", talk.clone(), |o| {
        through_socks(o, "socks5h", b"http://origin.example/a");
        o.proxy.make_mut().unwrap().user = Some(b"u".to_vec());
        o.proxy.make_mut().unwrap().password = Some(b"p".to_vec());
    });
    assert_eq!(ran.result, Ok(()));
    let mut want =
        b"\x05\x02\x00\x02\x01\x01u\x01p\x05\x01\x00\x03\x0eorigin.example\x00\x50".to_vec();
    want.extend_from_slice(
        b"GET /a HTTP/1.1\r\nHost: origin.example\r\nUser-Agent: curl/test\r\nAccept: */*\r\n\r\n",
    );
    assert_eq!(
        String::from_utf8_lossy(&ran.request),
        String::from_utf8_lossy(&want)
    );
    assert_eq!(ran.easy.report().connects(), 1);
    let said = ran.seen.text();
    let via = format!(" to origin.example port 80 (via 127.0.0.1 port {PORT})\n");
    assert!(
        said.iter()
            .any(|l| l.starts_with("Opened SOCKS connection from ") && l.ends_with(&via)),
        "{said:?}"
    );
}

/// A SOCKS4 proxy is asked for the IPv4 address the name resolves to
/// here, with an empty user.
#[test]
fn a_socks4_proxy_is_asked_for_the_address_resolved_here() {
    let talk = Conversation::replies(&[b"\x00\x5a\x00\x00\x00\x00\x00\x00", OK], false).per_send();
    let mut m = serving(Peer::Accepts, &[&talk]);
    let ran = get(&mut m, "/", talk.clone(), |o| {
        through_socks(o, "socks4", b"http://localhost:8990/a");
    });
    assert_eq!(ran.result, Ok(()));
    assert!(
        ran.request
            .starts_with(b"\x04\x01\x23\x1e\x7f\x00\x00\x01\x00GET /a HTTP/1.1\r\n"),
        "{:?}",
        String::from_utf8_lossy(&ran.request)
    );
}

/// A SOCKS proxy that cannot connect fails the transfer with its error,
/// kept for `CURLINFO_PROXY_ERROR`.
#[test]
fn a_socks_refusal_fails_with_the_proxy_s_error() {
    let refused = b"\x05\x05\x00\x01\x00\x00\x00\x00\x00\x00";
    let talk = Conversation::replies(&[b"\x05\x00", refused], false).per_send();
    let mut m = serving(Peer::Accepts, &[&talk]);
    let ran = get(&mut m, "/", talk.clone(), |o| {
        through_socks(o, "socks5h", b"http://origin.example/a");
    });
    assert_eq!(ran.result, Err(ErrorKind::Proxy));
    let report = ran.easy.report();
    assert_eq!(
        report.proxy_error(),
        Some(crate::conn::ProxyError::ReplyConnectionRefused)
    );
    assert!(
        ran.seen
            .text()
            .iter()
            .any(|l| l == "cannot complete SOCKS5 connection to origin.example. (5)\n"),
        "{:?}",
        ran.seen.text()
    );
}

/// A connection whose SOCKS5 proxy did not authenticate the user serves
/// no transfer that insists it must (test 1744); one it did serves both.
#[test]
fn an_unauthenticated_socks5_connection_serves_no_transfer_insisting() {
    let first = Conversation::replies(&[b"\x05\x00", SOCKS5_GRANTED, OK], false).per_send();
    let second =
        Conversation::replies(&[b"\x05\x02", b"\x01\x00", SOCKS5_GRANTED, OK], false).per_send();
    let mut m = serving(Peer::Accepts, &[&first, &second]);
    let creds = |o: &mut Options| {
        through_socks(o, "socks5h", b"http://origin.example/a");
        o.proxy.make_mut().unwrap().user = Some(b"u".to_vec());
        o.proxy.make_mut().unwrap().password = Some(b"p".to_vec());
    };
    let ran = get(&mut m, "/", first.clone(), creds);
    assert_eq!(ran.result, Ok(()));
    let ran = get_with(&mut m, ran.easy, "/", second.clone(), |o| {
        creds(o);
        o.proxy.make_mut().unwrap().socks5_auth.only = true;
    });
    assert_eq!(ran.result, Ok(()));
    assert_eq!(ran.easy.report().connects(), 1, "a new connection");
    assert!(second.received().starts_with(b"\x05\x01\x02"));
    // The one that authenticated is reused, insisting or not.
    let ran = get_with(&mut m, ran.easy, "/", second.clone(), |o| {
        creds(o);
        o.proxy.make_mut().unwrap().socks5_auth.only = true;
    });
    assert_eq!(ran.easy.report().connects(), 0, "reused");
}

/// The first line of `bytes`, and what follows it.
fn first_line(bytes: &[u8]) -> (String, &[u8]) {
    let end = bytes.windows(2).position(|w| w == b"\r\n").expect("a line") + 2;
    (
        String::from_utf8_lossy(&bytes[..end]).into_owned(),
        &bytes[end..],
    )
}

/// A new connection says where it comes from before its first request,
/// with the socket's addresses and ports (test 1455); one reused does
/// not again, and the connection is counted once.
#[test]
fn a_new_connection_sends_the_proxy_protocol_s_line_first() {
    let (mut m, talk, _) = server(&[OK, OK], false);
    let haproxy = |o: &mut Options| o.proxy.make_mut().unwrap().haproxy = true;
    let ran = get(&mut m, "/a", talk.clone(), haproxy);
    assert_eq!(ran.result, Ok(()));
    assert_eq!(ran.easy.report().connects(), 1);
    let (line, rest) = first_line(&ran.request);
    let words: Vec<&str> = line.trim_end().split(' ').collect();
    assert_eq!(
        words[..4],
        ["PROXY", "TCP4", "127.0.0.1", "127.0.0.1"],
        "{line}"
    );
    assert!(words[4].parse::<u16>().is_ok());
    assert_eq!(words[5], PORT.to_string());
    assert_eq!(rest, request_of("/a"));
    assert!(
        !ran.seen.of("out").concat().starts_with(b"PROXY"),
        "not traced as sent"
    );
    let ran = get_with(&mut m, ran.easy, "/b", talk.clone(), haproxy);
    assert_eq!(ran.easy.report().connects(), 0, "reused");
    let mut want = request_of("/a");
    want.extend_from_slice(&request_of("/b"));
    assert_eq!(first_line(&ran.request).1, want, "no line again");
}

/// An address the application gives is said as both ends, its family
/// IPv6 unless it is an IPv4 address (test 3220); the ports stay the
/// socket's.
#[test]
fn the_proxy_protocol_s_line_says_the_address_given() {
    for (ip, family) in [("2a04:4e42::347", "TCP6"), ("192.168.1.1", "TCP4")] {
        let (mut m, talk, _) = server(&[OK], false);
        let ran = get(&mut m, "/", talk, |o| {
            o.proxy.make_mut().unwrap().haproxy = true;
            o.proxy.make_mut().unwrap().haproxy_client_ip = Some(ip.as_bytes().to_vec());
        });
        let (line, _) = first_line(&ran.request);
        let want = format!("PROXY {family} {ip} {ip} ");
        assert!(line.starts_with(&want), "{line}");
        assert!(line.ends_with(&format!(" {PORT}\r\n")), "{line}");
    }
}

/// Through a tunnel, the line goes once it is up, ahead of the origin's
/// request, with the addresses of the socket to the proxy (test 3028).
#[test]
fn the_proxy_protocol_s_line_goes_through_a_tunnel() {
    let (mut m, talk, _) = server(&[TUNNEL_UP, OK], false);
    let ran = get(&mut m, "/", talk, |o| {
        o.set_url(Some(b"http://origin.example/a")).unwrap();
        o.proxy.make_mut().unwrap().url = Some(format!("127.0.0.1:{PORT}").into_bytes());
        o.proxy.make_mut().unwrap().tunnel = true;
        o.proxy.make_mut().unwrap().haproxy = true;
    });
    assert_eq!(ran.result, Ok(()));
    let connect = connect_of("");
    assert!(ran.request.starts_with(connect.as_bytes()));
    let (line, rest) = first_line(&ran.request[connect.len()..]);
    assert!(
        line.starts_with("PROXY TCP4 127.0.0.1 127.0.0.1 "),
        "{line}"
    );
    assert!(rest.starts_with(b"GET /a HTTP/1.1\r\n"));
}

/// Behind a SOCKS proxy the line goes once its handshake is made, and
/// behind a SOCKS pre-proxy and a tunnel only once the tunnel is up too,
/// ahead of the origin's request (`cf_setup_connect`: SOCKS, then the
/// HTTP proxy, then the PROXY protocol). Whether it goes is read then:
/// turned on as the tunnel's answer comes, it goes.
#[test]
fn the_proxy_protocol_s_line_follows_every_proxy_s_handshake() {
    struct OnInTheTunnel;
    impl HeaderHandler for OnInTheTunnel {
        fn header(&self, cx: &mut TransferCx<'_>, _: &[u8], origin: HeaderOrigin) -> Write {
            if origin == HeaderOrigin::Connect {
                let me = cx.me();
                let o = cx.options_mut(me).unwrap();
                o.proxy.make_mut().unwrap().haproxy = true;
            }
            Write::Accepted
        }
    }
    let socks = b"\x05\x01\x00\x05\x01\x00\x03\x0eorigin.example\x00\x50";
    let talk = Conversation::replies(&[b"\x05\x00", SOCKS5_GRANTED, OK], false).per_send();
    let mut m = serving(Peer::Accepts, &[&talk]);
    let ran = get(&mut m, "/", talk.clone(), |o| {
        o.set_url(Some(b"http://origin.example/a")).unwrap();
        o.proxy.make_mut().unwrap().url = Some(format!("socks5h://127.0.0.1:{PORT}").into_bytes());
        o.proxy.make_mut().unwrap().haproxy = true;
    });
    assert_eq!(ran.result, Ok(()));
    let sent = &ran.request;
    assert!(sent.starts_with(socks), "{}", sent.escape_ascii());
    let (line, rest) = first_line(&sent[socks.len()..]);
    assert!(
        line.starts_with("PROXY TCP4 127.0.0.1 127.0.0.1 "),
        "{line}"
    );
    assert!(rest.starts_with(b"GET /a HTTP/1.1\r\n"));

    let replies: [&[u8]; 4] = [b"\x05\x00", SOCKS5_GRANTED, TUNNEL_UP, OK];
    let talk = Conversation::replies(&replies, false).per_send();
    let mut m = serving(Peer::Accepts, &[&talk]);
    let ran = get(&mut m, "/", talk.clone(), |o| {
        o.set_url(Some(b"http://origin.example/a")).unwrap();
        o.proxy.make_mut().unwrap().url = Some(b"http://proxy.example:3128".to_vec());
        o.proxy.make_mut().unwrap().tunnel = true;
        o.proxy.make_mut().unwrap().pre_proxy =
            Some(format!("socks5h://127.0.0.1:{PORT}").into_bytes());
        o.callbacks.header = Some(Handler::header(OnInTheTunnel).unwrap());
    });
    assert_eq!(ran.result, Ok(()));
    let socks = b"\x05\x01\x00\x05\x01\x00\x03\x0dproxy.example\x0c\x38";
    let mut want = socks.to_vec();
    want.extend_from_slice(connect_of("").as_bytes());
    let sent = &ran.request;
    assert!(sent.starts_with(&want), "{}", sent.escape_ascii());
    let (line, rest) = first_line(&sent[want.len()..]);
    assert!(
        line.starts_with("PROXY TCP4 127.0.0.1 127.0.0.1 "),
        "{line}"
    );
    assert!(rest.starts_with(b"GET /a HTTP/1.1\r\n"));
}

/// The PROXY line goes over the connection as it is dialed: until the
/// line is sent the connection is not open, so nothing can take it for
/// one that is (cf-haproxy.c's filter is part of the connect).
#[test]
fn a_connection_is_not_open_until_its_proxy_line_is_sent() {
    let talk = Conversation::replies(&[OK], false).stalling_sends(1);
    let mut m = serving(Peer::Accepts, &[&talk]);
    let mut e = Easy::new();
    let url = format!("http://127.0.0.1:{PORT}/");
    e.options_mut().set_url(Some(url.as_bytes())).unwrap();
    e.options_mut().proxy.make_mut().unwrap().haproxy = true;
    let id = m.add(Box::new(e), (), &mut NoEvents).unwrap();
    m.perform(&mut NoEvents).unwrap();
    let lease = m.state_of(id).lease().expect("a connection held");
    assert!(!lease.is_up(), "open with its line unsent");
    assert_eq!(talk.received(), b"");
    let result = drive_to_completion(&mut m, id, &mut NoEvents).unwrap();
    assert_eq!(result, Ok(()));
    let sent = talk.received();
    let (line, rest) = first_line(&sent);
    assert!(
        line.starts_with("PROXY TCP4 127.0.0.1 127.0.0.1 "),
        "{line}"
    );
    assert!(rest.starts_with(b"GET / HTTP/1.1\r\n"));
}

/// A transfer taken out while its tunnel is set up leaves nothing for
/// the next to reuse: the connection to the proxy closes with it, and
/// the next makes its own.
#[test]
fn a_transfer_removed_mid_connect_leaves_no_connection_to_reuse() {
    let silent = Conversation::replies(&[], false);
    let fresh = Conversation::replies(&[TUNNEL_UP, OK], false);
    let mut m = serving(Peer::Accepts, &[&silent, &fresh]);
    let mut e = Easy::new();
    tunneled(e.options_mut());
    let id = m.add(Box::new(e), (), &mut NoEvents).unwrap();
    m.perform(&mut NoEvents).unwrap();
    // The connect started in the first pass is taken in the next.
    m.perform(&mut NoEvents).unwrap();
    assert!(silent.received().starts_with(b"CONNECT origin.example:80 "));
    m.remove(id, &mut NoEvents).unwrap();
    let ran = get(&mut m, "/", fresh.clone(), tunneled);
    assert_eq!(ran.result, Ok(()));
    assert_eq!(ran.seen.body(), b"ok\n");
    assert!(fresh.received().starts_with(b"CONNECT origin.example:80 "));
}

/// Behind a SOCKS5 pre-proxy at `PORT`, the HTTP proxy is asked for by
/// name, then given the request whole, over the one connection, traced
/// as C traces it (test 2055). The proxy's user is the HTTP proxy's
/// alone: the pre-proxy has only what its URL gives.
#[test]
fn a_pre_proxy_reaches_the_http_proxy_that_forwards() {
    let talk = Conversation::replies(&[b"\x05\x00", SOCKS5_GRANTED, OK], false).per_send();
    let mut m = serving(Peer::Accepts, &[&talk]);
    let ran = get(&mut m, "/", talk.clone(), |o| {
        o.set_url(Some(b"http://origin.example/a")).unwrap();
        o.proxy.make_mut().unwrap().url = Some(b"http://proxy.example:3128".to_vec());
        o.proxy.make_mut().unwrap().pre_proxy =
            Some(format!("socks5h://127.0.0.1:{PORT}").into_bytes());
        o.proxy.make_mut().unwrap().user = Some(b"u".to_vec());
        o.proxy.make_mut().unwrap().password = Some(b"p".to_vec());
    });
    assert_eq!(ran.result, Ok(()));
    let text = String::from_utf8_lossy(&ran.request).into_owned();
    assert!(
        text.contains("\r\nProxy-Authorization: Basic dTpw\r\n"),
        "{text}"
    );
    let mut want = b"\x05\x01\x00\x05\x01\x00\x03\x0dproxy.example\x0c\x38".to_vec();
    want.extend_from_slice(b"GET http://origin.example/a HTTP/1.1\r\n");
    assert!(
        ran.request.starts_with(&want),
        "{:?}",
        String::from_utf8_lossy(&ran.request)
    );
    assert_eq!(ran.easy.report().connects(), 1);
    let said = ran.seen.text();
    let via = format!(" to proxy.example port 3128 (via 127.0.0.1 port {PORT})\n");
    assert!(said.iter().any(|l| l.ends_with(&via)), "{said:?}");
    let up = format!("Established connection to 127.0.0.1 (127.0.0.1 port {PORT}) from ");
    assert!(said.iter().any(|l| l.starts_with(&up)), "{said:?}");
}

/// Behind a pre-proxy, an HTTP proxy asked to tunnel is sent its
/// `CONNECT` once the SOCKS proxy has connected to it.
#[test]
fn a_pre_proxy_reaches_the_http_proxy_that_tunnels() {
    let replies: [&[u8]; 4] = [b"\x05\x00", SOCKS5_GRANTED, TUNNEL_UP, OK];
    let talk = Conversation::replies(&replies, false).per_send();
    let mut m = serving(Peer::Accepts, &[&talk]);
    let ran = get(&mut m, "/", talk.clone(), |o| {
        o.set_url(Some(b"http://origin.example/a")).unwrap();
        o.proxy.make_mut().unwrap().url = Some(b"http://proxy.example:3128".to_vec());
        o.proxy.make_mut().unwrap().tunnel = true;
        o.proxy.make_mut().unwrap().pre_proxy =
            Some(format!("socks5h://127.0.0.1:{PORT}").into_bytes());
    });
    assert_eq!(ran.result, Ok(()));
    let socks = b"\x05\x01\x00\x05\x01\x00\x03\x0dproxy.example\x0c\x38";
    let mut want = socks.to_vec();
    want.extend_from_slice(connect_of("").as_bytes());
    want.extend_from_slice(b"GET /a HTTP/1.1\r\n");
    assert!(
        ran.request.starts_with(&want),
        "{:?}",
        String::from_utf8_lossy(&ran.request)
    );
    assert_eq!(ran.easy.report().connect_code(), Some(200));
    assert_eq!(ran.easy.report().connects(), 1);
}

/// A pre-proxy alone is the SOCKS proxy, SOCKS4 unless its scheme says
/// otherwise; one that is HTTP, or in front of a SOCKS proxy, is refused
/// as C refuses it.
#[test]
fn a_pre_proxy_alone_is_the_socks_proxy_and_only_socks() {
    let talk = Conversation::replies(&[b"\x00\x5a\x00\x00\x00\x00\x00\x00", OK], false).per_send();
    let mut m = serving(Peer::Accepts, &[&talk]);
    let ran = get(&mut m, "/", talk.clone(), |o| {
        o.set_url(Some(b"http://localhost:8990/a")).unwrap();
        o.proxy.make_mut().unwrap().pre_proxy = Some(format!("127.0.0.1:{PORT}").into_bytes());
    });
    assert_eq!(ran.result, Ok(()));
    assert!(
        ran.request
            .starts_with(b"\x04\x01\x23\x1e\x7f\x00\x00\x01\x00GET /a ")
    );
    for (proxy, pre, said) in [
        (
            None,
            "http://127.0.0.1:1",
            "Unsupported pre-proxy type for 'http://127.0.0.1:1'\n",
        ),
        (
            Some("socks5://127.0.0.1:2"),
            "socks5://127.0.0.1:1",
            "Having a SOCKS pre-proxy and proxy is not supported with 'socks5://127.0.0.1:2'\n",
        ),
    ] {
        let (mut m, talk, _) = server(&[OK], false);
        let ran = get(&mut m, "/", talk, |o| {
            o.proxy.make_mut().unwrap().url = proxy.map(|p| p.as_bytes().to_vec());
            o.proxy.make_mut().unwrap().pre_proxy = Some(pre.as_bytes().to_vec());
        });
        assert_eq!(ran.result, Err(ErrorKind::CouldntResolveProxy));
        assert!(
            ran.seen.text().iter().any(|l| l == said),
            "{:?}",
            ran.seen.text()
        );
    }
}

/// A proxy whose user does not decode fails the transfer as a bad URL,
/// with nothing said, as C's `parse_proxy` does.
#[test]
fn a_proxy_user_that_does_not_decode_is_a_bad_url() {
    let (mut m, talk, _) = server(&[OK], false);
    let ran = get(&mut m, "/", talk.clone(), |o| {
        o.proxy.make_mut().unwrap().url =
            Some(format!("http://u%01@127.0.0.1:{PORT}").into_bytes());
    });
    assert_eq!(ran.result, Err(ErrorKind::UrlMalformat));
    let said = ran.seen.text();
    assert!(
        !said.iter().any(|l| l.starts_with("Unsupported proxy")),
        "{said:?}"
    );
    assert_eq!(talk.received(), b"");
}

/// A tunnel's `CONNECT`, as test 1287's proxy sees it: the origin's
/// authority, and only what the proxy is given.
fn connect_of(proxy_authorization: &str) -> String {
    format!(
        "CONNECT origin.example:80 HTTP/1.1\r\nHost: origin.example:80\r\n\
         {proxy_authorization}User-Agent: curl/test\r\nProxy-Connection: Keep-Alive\r\n\r\n"
    )
}

const TUNNEL_UP: &[u8] = b"HTTP/1.1 200 Fine\r\n\r\n";

/// Through a proxy that tunnels, its 407 is answered with another
/// `CONNECT` over the same connection, its body dropped; the request then
/// goes through the tunnel as to the origin, and the proxy's status is
/// kept (`CURLINFO_HTTP_CONNECTCODE`).
#[test]
fn a_tunnel_answers_a_407_over_the_same_connection() {
    let challenge = b"HTTP/1.1 407 Who\r\n\
        Proxy-Authenticate: Basic realm=\"p\"\r\nContent-Length: 3\r\n\r\nabc";
    let (mut m, talk, _) = server(&[challenge, TUNNEL_UP, OK], false);
    let ran = get(&mut m, "/", talk, |o| {
        o.set_url(Some(b"http://origin.example/a")).unwrap();
        o.proxy.make_mut().unwrap().url = Some(format!("127.0.0.1:{PORT}").into_bytes());
        o.proxy.make_mut().unwrap().tunnel = true;
        o.proxy.make_mut().unwrap().user = Some(b"u".to_vec());
        o.proxy.make_mut().unwrap().password = Some(b"p".to_vec());
        o.proxy.make_mut().unwrap().auth = crate::options::HttpAuth(AuthMethods::ANY);
    });
    assert_eq!(ran.result, Ok(()));
    let text = String::from_utf8_lossy(&ran.request).into_owned();
    let get = "GET /a HTTP/1.1\r\nHost: origin.example\r\nUser-Agent: curl/test\r\n\
               Accept: */*\r\n\r\n";
    assert_eq!(
        text,
        connect_of("") + &connect_of("Proxy-Authorization: Basic dTpw\r\n") + get
    );
    let report = ran.easy.report();
    assert_eq!(report.connect_code(), Some(200));
    assert_eq!(report.connects(), 1);
    assert_eq!(report.proxy_auth_used(), AuthMethods::BASIC);
    let said = ran.seen.text();
    assert!(
        said.iter()
            .any(|l| l == "CONNECT tunnel established, response 200\n"),
        "{said:?}"
    );
}

/// A proxy that closes the connection on its 407 is connected to again,
/// and asked again with its credentials (`Connect me again please`).
#[test]
fn a_tunnel_redials_when_the_proxy_closes_on_its_407() {
    let challenge: &[u8] = b"HTTP/1.1 407 Who\r\n\
        Proxy-Authenticate: Basic realm=\"p\"\r\nProxy-Connection: close\r\n\
        Content-Length: 0\r\n\r\n";
    let first = Conversation::replies(&[challenge], true);
    let second = Conversation::replies(&[TUNNEL_UP, OK], false);
    let mut m = serving(Peer::Accepts, &[&first, &second]);
    let ran = get(&mut m, "/", second.clone(), |o| {
        o.set_url(Some(b"http://origin.example/a")).unwrap();
        o.proxy.make_mut().unwrap().url = Some(format!("127.0.0.1:{PORT}").into_bytes());
        o.proxy.make_mut().unwrap().tunnel = true;
        o.proxy.make_mut().unwrap().user = Some(b"u".to_vec());
        o.proxy.make_mut().unwrap().password = Some(b"p".to_vec());
        o.proxy.make_mut().unwrap().auth = crate::options::HttpAuth(AuthMethods::ANY);
    });
    assert_eq!(ran.result, Ok(()));
    assert_eq!(String::from_utf8_lossy(&first.received()), connect_of(""));
    let text = String::from_utf8_lossy(&second.received()).into_owned();
    assert!(
        text.starts_with(&connect_of("Proxy-Authorization: Basic dTpw\r\n")),
        "{text}"
    );
    assert_eq!(ran.easy.report().connects(), 2);
    let said = ran.seen.text();
    assert!(
        said.iter().any(|l| l == "Connect me again please\n"),
        "{said:?}"
    );
}

/// Suppressed, the proxy's answer to `CONNECT` reaches neither the header
/// handler nor the included output, but is still kept with the headers
/// (`CURLOPT_SUPPRESS_CONNECT_HEADERS`, ahead of which C collects them).
#[test]
fn suppressed_connect_headers_are_kept_and_not_delivered() {
    use crate::report::{Origins, Request};
    let up: &[u8] = b"HTTP/1.1 200 Fine\r\nVia: tunnel\r\n\r\n";
    for suppress in [false, true] {
        let (mut m, talk, _) = server(&[up, OK], false);
        let ran = get(&mut m, "/", talk, |o| {
            o.set_url(Some(b"http://origin.example/a")).unwrap();
            o.proxy.make_mut().unwrap().url = Some(format!("127.0.0.1:{PORT}").into_bytes());
            o.proxy.make_mut().unwrap().tunnel = true;
            o.proxy.make_mut().unwrap().suppress_connect_headers = suppress;
            o.output.include_header = true;
        });
        assert_eq!(ran.result, Ok(()));
        let delivered = ran.seen.of("header").contains(&b"Via: tunnel\r\n".to_vec());
        let included = String::from_utf8_lossy(&ran.seen.body()).contains("Via: tunnel");
        assert_eq!(
            (delivered, included),
            (!suppress, !suppress),
            "suppress {suppress}"
        );
        let status = ran
            .seen
            .of("header")
            .contains(&b"HTTP/1.1 200 Fine\r\n".to_vec());
        assert_eq!(status, !suppress, "suppress {suppress}: the status line");
        let kept = ran.easy.report().headers().get(
            b"Via",
            0,
            Origins::from(HeaderOrigin::Connect),
            Request::Last,
        );
        assert!(kept.is_ok(), "suppress {suppress}");
    }
}

/// Through a tunnel at `PORT` to `http://origin.example/a`.
fn tunneled(o: &mut Options) {
    o.set_url(Some(b"http://origin.example/a")).unwrap();
    o.proxy.make_mut().unwrap().url = Some(format!("127.0.0.1:{PORT}").into_bytes());
    o.proxy.make_mut().unwrap().tunnel = true;
}

/// A transfer of `m` over `talk` started with the options `set` makes,
/// run as far as it goes without waiting; what its socket waits for.
fn waiting(m: &mut Multi, set: impl FnOnce(&mut Options)) -> Vec<crate::conn::io::Events> {
    let mut e = Easy::new();
    let url = format!("http://127.0.0.1:{PORT}/");
    e.options_mut().set_url(Some(url.as_bytes())).unwrap();
    set(e.options_mut());
    m.add(Box::new(e), (), &mut NoEvents).unwrap();
    m.perform(&mut NoEvents).unwrap();
    // The connect started in the first pass is taken in the next.
    m.perform(&mut NoEvents).unwrap();
    let mut seen = Vec::new();
    m.sockets(&mut NoEvents, |_, events| seen.push(events));
    seen
}

/// A proxy's handshake waits to write what it could not send yet, then
/// to read the answer: a tunnel's `CONNECT`, a SOCKS proxy's request, and
/// the PROXY protocol's line, which waits for nothing else. It waits to
/// read throughout, as C's socket filter, connected but not yet in use,
/// adds (`cf_socket_adjust_pollset`).
#[test]
fn a_proxy_handshake_waits_to_send_then_to_read() {
    use crate::conn::io::Events;
    let stalled = |replies: &[&[u8]]| Conversation::replies(replies, false).stalling_sends(1);
    let talk = stalled(&[]);
    let mut m = serving(Peer::Accepts, &[&talk]);
    assert_eq!(waiting(&mut m, tunneled), [Events::OUT | Events::IN]);
    m.perform(&mut NoEvents).unwrap();
    let mut seen = Vec::new();
    m.sockets(&mut NoEvents, |_, events| seen.push(events));
    assert_eq!(seen, [Events::IN], "the CONNECT sent, its answer awaited");
    assert!(
        talk.received()
            .starts_with(b"CONNECT origin.example:80 HTTP/1.1\r\n")
    );
    let talk = stalled(&[]).per_send();
    let mut m = serving(Peer::Accepts, &[&talk]);
    let socks = |o: &mut Options| through_socks(o, "socks5h", b"http://origin.example/a");
    assert_eq!(waiting(&mut m, socks), [Events::OUT | Events::IN]);
    m.perform(&mut NoEvents).unwrap();
    let mut seen = Vec::new();
    m.sockets(&mut NoEvents, |_, events| seen.push(events));
    assert_eq!(seen, [Events::IN], "the offer sent, the pick awaited");
    let talk = stalled(&[OK]);
    let mut m = serving(Peer::Accepts, &[&talk]);
    assert_eq!(
        waiting(&mut m, |o| o.proxy.make_mut().unwrap().haproxy = true),
        [Events::OUT | Events::IN]
    );
}

/// A tunnel's `CONNECT` is traced as sent, and its answer's head counts
/// in the header size (`Curl_bump_headersize`).
#[test]
fn a_tunnel_s_connect_is_traced_and_its_answer_counted() {
    let (mut m, talk, _) = server(&[TUNNEL_UP, OK], false);
    let ran = get(&mut m, "/", talk, tunneled);
    assert_eq!(ran.result, Ok(()));
    assert_eq!(ran.seen.of("out")[0], connect_of("").as_bytes());
    let head = OK.len() - b"ok\n".len();
    assert_eq!(
        ran.easy.report().sizes().header(),
        (TUNNEL_UP.len() + head) as u64
    );
}

/// Bytes the proxy sent after its answer to `CONNECT`, read with it, are
/// the tunnel's first: the transfer reads them without waiting for its
/// socket, which has nothing more to say. The answer is read in bulk, the
/// response behind it in the same read. C reads the answer a byte at a
/// time (`recv_CONNECT_resp`), its filter having no way to hand bytes
/// past it back up the chain, so it makes a read for each byte of the
/// answer and traces each (`DIVERGENCE.md`).
#[test]
fn bytes_after_a_tunnel_s_answer_are_read_first() {
    let up_and_answered = [TUNNEL_UP, OK].concat();
    let (mut m, talk, clock) = server(&[&up_and_answered], false);
    let start = clock.now();
    let ran = get(&mut m, "/", talk.clone(), tunneled);
    assert_eq!(ran.result, Ok(()));
    assert_eq!(ran.seen.body(), b"ok\n");
    assert_eq!(clock.now(), start, "the transfer waited on its socket");
    assert_eq!(talk.reads().0, 1, "the answer and the response in one read");
}

/// An answer to `CONNECT` of `total` head bytes, of lines as long as C's
/// buffer takes.
fn tunnel_up_of(total: usize) -> Vec<u8> {
    let mut head = b"HTTP/1.1 200 Fine\r\n".to_vec();
    while head.len() + 2 < total {
        let line = (total - 2 - head.len()).clamp(5, 16_000);
        head.extend_from_slice(b"X: ");
        head.resize(head.len() + line - 5, b'a');
        head.extend_from_slice(b"\r\n");
    }
    head.extend_from_slice(b"\r\n");
    assert_eq!(head.len(), total);
    head
}

/// An answer to `CONNECT` is held to C's limit on a response's head
/// bytes, as a response is.
#[test]
fn a_tunnel_s_answer_is_held_to_the_head_limit() {
    use crate::proto::http1::fields::MAX_HEADERS;
    let at_limit = tunnel_up_of(MAX_HEADERS);
    let (mut m, talk, _) = server(&[&at_limit, OK], false);
    assert_eq!(get(&mut m, "/", talk, tunneled).result, Ok(()));
    let over = tunnel_up_of(MAX_HEADERS + 1);
    let (mut m, talk, _) = server(&[&over, OK], false);
    let ran = get(&mut m, "/", talk, tunneled);
    assert_eq!(ran.result, Err(ErrorKind::RecvError));
    let said = ran.seen.text();
    let want = format!(
        "Too large response headers: {} > {MAX_HEADERS}\n",
        MAX_HEADERS + 1
    );
    assert!(said.contains(&want), "{said:?}");
}

/// A proxy that closes mid-answer aborts the tunnel, though it offers a
/// method, when it was sent no credentials (`recv_CONNECT_resp`); the
/// line it had sent whole is still traced and delivered.
#[test]
fn a_proxy_closing_mid_answer_aborts_the_tunnel() {
    let challenge = "Proxy-Authenticate: Basic realm=\"p\"\r\n";
    let cut = format!("HTTP/1.1 407 Who\r\n{challenge}");
    let talk = Conversation::replies(&[cut.as_bytes()], true);
    let mut m = serving(Peer::Accepts, &[&talk]);
    let ran = get(&mut m, "/", talk, tunneled);
    assert_eq!(ran.result, Err(ErrorKind::RecvError));
    let said = ran.seen.text();
    assert!(
        said.iter().any(|l| l == "Proxy CONNECT aborted\n"),
        "{said:?}"
    );
    assert_eq!(ran.seen.of("in").last().unwrap(), challenge.as_bytes());
    assert_eq!(ran.seen.of("header").last().unwrap(), challenge.as_bytes());
}

/// A Digest proxy's 407, then its answer to the credentials cut off by
/// the proxy closing: a stale nonce, offering Digest again.
const DIGEST_407: &[u8] = b"HTTP/1.1 407 Who\r\n\
    Proxy-Authenticate: Digest realm=\"r\", nonce=\"n1\"\r\nContent-Length: 0\r\n\r\n";
const DIGEST_STALE_CUT: &[u8] = b"HTTP/1.1 407 Who\r\n\
    Proxy-Authenticate: Digest realm=\"r\", nonce=\"n2\", stale=true\r\n";

/// Through a tunnel to a Digest proxy, as user `u`.
fn tunneled_digest(o: &mut Options) {
    tunneled(o);
    o.proxy.make_mut().unwrap().user = Some(b"u".to_vec());
    o.proxy.make_mut().unwrap().password = Some(b"p".to_vec());
    o.proxy.make_mut().unwrap().auth = crate::options::HttpAuth(AuthMethods::DIGEST);
}

/// A proxy closing mid-answer to the `CONNECT` that carried credentials,
/// read before the tunnel waited on its socket again, while it offers a
/// method to retry, is a mere disconnect: the tunnel is connected again
/// and asked again, never over the closed connection
/// (`recv_CONNECT_resp`'s `close_connection`). Values from the C build
/// against a scripted proxy.
#[test]
fn a_proxy_closing_on_the_credentials_is_connected_to_again() {
    let first = Conversation::replies(&[DIGEST_407, DIGEST_STALE_CUT], true);
    let second = Conversation::replies(&[TUNNEL_UP, OK], false);
    let mut m = serving(Peer::Accepts, &[&first, &second]);
    let ran = get(&mut m, "/", second.clone(), tunneled_digest);
    assert_eq!(ran.result, Ok(()));
    let n1 = "Proxy-Authorization: Digest username=\"u\", realm=\"r\", nonce=\"n1\", \
              uri=\"origin.example:80\", response=\"32d7dc5cfe84590e13b74e7264428b0f\"\r\n";
    let n2 = "Proxy-Authorization: Digest username=\"u\", realm=\"r\", nonce=\"n2\", \
              uri=\"origin.example:80\", response=\"287634b6a228e2af593b063681ac96cc\"\r\n";
    assert_eq!(
        String::from_utf8_lossy(&first.received()),
        connect_of("") + &connect_of(n1)
    );
    let text = String::from_utf8_lossy(&second.received()).into_owned();
    assert!(text.starts_with(&connect_of(n2)), "{text}");
    assert_eq!(ran.easy.report().connects(), 2);
    let said = ran.seen.text();
    let closed = said
        .iter()
        .position(|l| l == "Proxy CONNECT connection closed\n");
    let again = said.iter().position(|l| l == "Connect me again please\n");
    assert!(closed.is_some() && closed < again, "{said:?}");
    // The proxy's name is not looked up again: the addresses it resolved
    // to are raced at once, as C's chain below its name's filter is
    // rebuilt.
    let trying = format!("  Trying 127.0.0.1:{PORT}...\n");
    assert_eq!(said.get(again.unwrap() + 1), Some(&trying), "{said:?}");
}

/// A proxy that closes on every answer asking for credentials is
/// connected to again five times, then given up on (`cf_setup_connect`'s
/// `retry_count`), as the C build does against a scripted proxy.
#[test]
fn a_proxy_closing_every_time_is_redialed_five_times() {
    let stale: &[u8] = b"HTTP/1.1 407 Who\r\n\
        Proxy-Authenticate: Digest realm=\"r\", nonce=\"n\", stale=true\r\n\
        Proxy-Connection: close\r\nContent-Length: 0\r\n\r\n";
    let first = Conversation::replies(&[DIGEST_407, stale], true);
    let talks: Vec<Conversation> = (0..6)
        .map(|_| Conversation::replies(&[stale], true))
        .collect();
    let all: Vec<&Conversation> = std::iter::once(&first).chain(&talks).collect();
    let mut m = serving(Peer::Accepts, &all);
    let ran = get(&mut m, "/", first.clone(), tunneled_digest);
    assert_eq!(ran.result, Err(ErrorKind::CouldntConnect));
    let asked: Vec<bool> = talks.iter().map(|t| !t.received().is_empty()).collect();
    assert_eq!(asked, [true, true, true, true, true, false]);
}

/// The name a setup finds in the cache is the one it looked up: through
/// a tunnel, the proxy's, not the origin's (`hostip_resolv`'s
/// `peer->hostname`), as the C build traces it.
#[test]
fn a_proxy_s_name_is_the_one_found_in_the_cache() {
    let (mut m, talk, _) = server(&[TUNNEL_UP, OK], false);
    let ran = get(&mut m, "/", talk, |o| {
        tunneled(o);
        o.proxy.make_mut().unwrap().url = Some(format!("proxy.test:{PORT}").into_bytes());
        let entry = format!("proxy.test:{PORT}:127.0.0.1");
        o.resolve.set([entry.as_bytes()]).unwrap();
    });
    assert_eq!(ran.result, Ok(()));
    let said = ran.seen.text();
    assert!(
        said.iter()
            .any(|l| l == "Hostname proxy.test was found in DNS cache\n"),
        "{said:?}"
    );
}

/// Digest is the proxy's method from the first request, before it has a
/// challenge to answer: the trace names it though no header goes yet,
/// through a tunnel and to a proxy forwarding the request alike
/// (`output_auth_headers`), as the C build traces it.
#[test]
fn a_proxy_s_digest_is_traced_before_its_first_challenge() {
    for tunnel in [true, false] {
        let (mut m, talk, _) = server(&[if tunnel { TUNNEL_UP } else { OK }, OK], false);
        let ran = get(&mut m, "/", talk, |o| {
            tunneled_digest(o);
            o.proxy.make_mut().unwrap().tunnel = tunnel;
        });
        assert_eq!(ran.result, Ok(()), "tunnel {tunnel}");
        let first = if tunnel { "CONNECT " } else { "GET " };
        let text = String::from_utf8_lossy(&ran.request).into_owned();
        assert!(text.starts_with(first), "{text}");
        assert!(!text.contains("Proxy-Authorization"), "{text}");
        let line = b"Proxy auth using Digest with user 'u'\n";
        let (traced, sent) = {
            let seen = ran.seen.0.lock().unwrap();
            let traced = seen.iter().position(|(w, l)| *w == "text" && l == line);
            (traced, seen.iter().position(|(w, _)| *w == "out"))
        };
        assert!(
            traced.is_some_and(|t| sent.is_some_and(|s| t < s)),
            "tunnel {tunnel}: {:?}",
            ran.seen.text()
        );
        assert_eq!(ran.easy.report().proxy_auth_used(), AuthMethods::DIGEST);
    }
}

/// The progress calls and the lines traced, in their order: a run of
/// progress calls as `[xN]`.
#[derive(Clone, Default)]
struct Interleaved(Arc<Mutex<Vec<String>>>);

impl Interleaved {
    fn push(&self, what: String) {
        self.0.lock().unwrap().push(what);
    }

    /// From the line starting `from`, up to the one starting `to`.
    fn between(&self, from: &str, to: &str) -> Vec<String> {
        let all = self.0.lock().unwrap();
        let start = all.iter().position(|l| l.starts_with(from)).unwrap();
        let end = start + all[start..].iter().position(|l| l.starts_with(to)).unwrap();
        all[start..=end].to_vec()
    }
}

impl crate::handler::ProgressHandler for Interleaved {
    fn progress(
        &self,
        _: &mut TransferCx<'_>,
        _: crate::handler::ProgressNow,
    ) -> crate::handler::ProgressVerdict {
        let mut all = self.0.lock().unwrap();
        let n = match all.last().and_then(|l| l.strip_prefix("[x")) {
            Some(n) => n.trim_end_matches(']').parse::<u32>().unwrap(),
            None => 0,
        };
        if n > 0 {
            all.pop();
        }
        all.push(format!("[x{}]", n + 1));
        crate::handler::ProgressVerdict::Continue
    }
}

impl DebugHandler for Interleaved {
    fn debug(&self, _: &mut TransferCx<'_>, kind: DebugKind, data: &[u8]) {
        if matches!(kind, DebugKind::Text | DebugKind::HeaderIn) {
            self.push(String::from_utf8_lossy(data).into_owned());
        }
    }
}

const ESTABLISHED: &[u8] = b"HTTP/1.1 200 Connection established\r\nX-Proxy: yes\r\n\r\n";

/// The progress handler is called for each byte of the proxy's answer to
/// `CONNECT`, before the line it ends is taken in (and so after the byte
/// after a header line, which says whether it goes on), and once more
/// each time the tunnel returns for more or has the answer, as the C
/// build calls it (`recv_CONNECT_resp`, `H1_CONNECT`; seen with a
/// program against it over a socket, where the answer comes after a
/// first look for it: 39, 14, 1 and 1 calls for this answer, and one
/// more before the first line for each wait in it).
#[test]
fn the_tunnel_takes_stock_for_each_byte_of_the_answer() {
    for (late, first) in [(false, 38), (true, 39)] {
        let mut talk = Conversation::replies(&[ESTABLISHED, OK], false);
        if late {
            talk = talk.late_replies();
        }
        let mut m = serving(Peer::Accepts, &[&talk]);
        let seen = Interleaved::default();
        let ran = get(&mut m, "/", talk.clone(), |o| {
            tunneled(o);
            o.progress =
                crate::options::Progress::Handler(Handler::progress(seen.clone()).unwrap());
            o.callbacks.debug = Some(Handler::debug(seen.clone()).unwrap());
        });
        assert_eq!(ran.result, Ok(()));
        let x = |n: u32| format!("[x{n}]");
        assert_eq!(
            seen.between("Establishing HTTP proxy tunnel", "CONNECT phase completed"),
            [
                "Establishing HTTP proxy tunnel to origin.example:80\n".to_string(),
                x(first),
                "HTTP/1.1 200 Connection established\r\n".to_string(),
                x(14),
                "X-Proxy: yes\r\n".to_string(),
                x(1),
                "\r\n".to_string(),
                x(1),
                "CONNECT phase completed for HTTP proxy\n".to_string(),
            ],
            "late {late}"
        );
    }
}

/// A progress handler's abort in the middle of the proxy's answer ends
/// the transfer there, as in the C build ("Callback aborted" at the
/// fifth call).
#[test]
fn a_progress_abort_ends_the_tunnel_at_once() {
    let talk = Conversation::replies(&[ESTABLISHED, OK], false);
    let mut m = serving(Peer::Accepts, &[&talk]);
    let aborts = AbortsAt {
        abort_at: 5,
        ..AbortsAt::default()
    };
    let ran = get(&mut m, "/", talk.clone(), |o| {
        tunneled(o);
        o.progress = crate::options::Progress::Handler(Handler::progress(aborts.clone()).unwrap());
    });
    assert_eq!(ran.result, Err(ErrorKind::AbortedByCallback));
    assert_eq!(aborts.calls.get(), 5);
    let said = ran.seen.text();
    assert!(said.contains(&"Callback aborted\n".to_string()), "{said:?}");
    assert!(
        !said.iter().any(|l| l.starts_with("CONNECT phase")),
        "{said:?}"
    );
}

/// The same close, read only after the tunnel waited on its socket for
/// the answer, aborts it: the credentials are no longer held
/// (`hd_proxy_auth`, freed as `cf_h1_proxy_connect` returns).
#[test]
fn a_proxy_closing_after_a_wait_aborts_the_tunnel() {
    let first = Conversation::replies(&[DIGEST_407, DIGEST_STALE_CUT], true).late_replies();
    let mut m = serving(Peer::Accepts, &[&first]);
    let ran = get(&mut m, "/", first.clone(), tunneled_digest);
    assert_eq!(ran.result, Err(ErrorKind::RecvError));
    let said = ran.seen.text();
    assert!(
        said.iter().any(|l| l == "Proxy CONNECT aborted\n"),
        "{said:?}"
    );
    assert!(
        !said
            .iter()
            .any(|l| l == "Proxy CONNECT connection closed\n"),
        "{said:?}"
    );
    let text = String::from_utf8_lossy(&first.received()).into_owned();
    assert_eq!(text.matches("CONNECT ").count(), 2, "{text}");
}

/// A 407 that offers again the method already sent is a refusal: its
/// body is not read, and the method used stays the one sent; one that
/// offers no method wanted leaves it so too.
#[test]
fn a_407_refusing_the_credentials_sent_ends_the_tunnel() {
    let basic: &[u8] = b"HTTP/1.1 407 Who\r\nProxy-Authenticate: Basic realm=\"p\"\r\n\
        Content-Length: 3\r\n\r\nabc";
    let digest: &[u8] = b"HTTP/1.1 407 Who\r\n\
        Proxy-Authenticate: Digest realm=\"r\", nonce=\"n\"\r\nContent-Length: 0\r\n\r\n";
    for answer in [basic, digest] {
        let (mut m, talk, _) = server(&[answer], false);
        let ran = get(&mut m, "/", talk, |o| {
            tunneled(o);
            o.proxy.make_mut().unwrap().user = Some(b"u".to_vec());
            o.proxy.make_mut().unwrap().password = Some(b"p".to_vec());
            o.proxy.make_mut().unwrap().auth = crate::options::HttpAuth(AuthMethods::BASIC);
        });
        assert_eq!(ran.result, Err(ErrorKind::CouldntConnect));
        let said = ran.seen.text();
        assert!(
            said.iter()
                .any(|l| l == "CONNECT tunnel failed, response 407\n"),
            "{said:?}"
        );
        assert!(!said.iter().any(|l| l.starts_with("Ignore ")), "{said:?}");
        assert_eq!(ran.easy.report().proxy_auth_used(), AuthMethods::BASIC);
    }
}

/// An answer the tunnel refuses fails it with the error C gives: a line
/// too long, and a dropped body's bad chunks.
#[test]
fn a_refused_answer_fails_the_tunnel_as_c() {
    let mut long = b"HTTP/1.1 200 Fine\r\nX: ".to_vec();
    long.resize(long.len() + 16_384, b'a');
    let bad_chunks: &[u8] = b"HTTP/1.1 407 Who\r\nTransfer-Encoding: chunked\r\n\r\nzz\r\n";
    for (answer, line) in [
        (&long[..], "CONNECT response too large\n"),
        (bad_chunks, "chunk hex-length char not a hex digit: 0x7a\n"),
    ] {
        let (mut m, talk, _) = server(&[answer], false);
        let ran = get(&mut m, "/", talk, tunneled);
        assert_eq!(ran.result, Err(ErrorKind::RecvError), "{line}");
        let said = ran.seen.text();
        assert!(said.iter().any(|l| l == line), "{said:?}");
    }
}

/// After a redirect to another host, the proxy's `Cookie` no longer goes
/// with the `CONNECT`, as an origin's credentials would not
/// (`Curl_auth_allowed_to_host`).
#[test]
fn a_tunnel_after_a_redirect_elsewhere_sends_no_cookie() {
    let first = Conversation::replies(&[TUNNEL_UP, &moved("http://other.example/b", false)], false);
    let second = Conversation::replies(&[TUNNEL_UP, OK], false);
    let mut m = serving(Peer::Accepts, &[&first, &second]);
    let ran = get(&mut m, "/", second.clone(), |o| {
        tunneled(o);
        o.http.follow = Follow::All;
        o.proxy.make_mut().unwrap().headers = UserHeaders::new([&b"Cookie: a=b"[..]]).unwrap();
    });
    assert_eq!(ran.result, Ok(()));
    let has_cookie = |talk: &Conversation| {
        let text = String::from_utf8_lossy(&talk.received()).into_owned();
        let (connect, _) = text.split_once("\r\n\r\n").unwrap();
        connect.contains("\r\nCookie: a=b")
    };
    assert!(has_cookie(&first), "to the first host");
    assert!(!has_cookie(&second), "not to the next");
    assert!(String::from_utf8_lossy(&second.received()).starts_with("CONNECT other.example:80 "));
}

/// A connection whose last response said HTTP/1.0 is sent HTTP/1.0 by
/// the next transfer to use it, as test 1078's second URL is
/// (`conn->httpversion_seen`).
#[test]
fn a_connection_that_answered_http10_is_asked_in_it() {
    let http10 = b"HTTP/1.0 200 OK\r\nConnection: keep-alive\r\nContent-Length: 0\r\n\r\n";
    let (mut m, talk, _) = server(&[http10, OK], false);
    assert_eq!(get(&mut m, "/a", talk.clone(), |_| {}).result, Ok(()));
    let ran = get(&mut m, "/b", talk, |_| {});
    assert_eq!(ran.result, Ok(()));
    let text = String::from_utf8_lossy(&ran.request).into_owned();
    let second = text.split_once("\r\n\r\n").map_or("", |(_, rest)| rest);
    assert!(second.starts_with("GET /b HTTP/1.0\r\n"), "{text}");
    assert_eq!(ran.easy.report().connects(), 0, "the connection was reused");
}

/// Through a proxy, the origin's Digest challenge is kept for the origin,
/// not for the proxy the connection goes to, and answered.
#[test]
fn an_origin_s_digest_is_answered_through_a_proxy() {
    let (mut m, talk, _) = server(&[DIGEST_CHALLENGE, OK], false);
    let ran = get(&mut m, "/", talk, |o| {
        o.set_url(Some(b"http://origin.example/a")).unwrap();
        o.proxy.make_mut().unwrap().url = Some(format!("127.0.0.1:{PORT}").into_bytes());
        *o.login.make_mut().unwrap() = crate::options::Login::from_pair(b"u:p").unwrap();
        o.http.auth = crate::options::HttpAuth(AuthMethods::DIGEST);
    });
    assert_eq!(ran.result, Ok(()));
    let text = String::from_utf8_lossy(&ran.request).into_owned();
    let second = text.rfind("GET ").unwrap();
    assert!(
        text[second..]
            .contains("\r\nAuthorization: Digest username=\"u\", realm=\"r\", nonce=\"n\""),
        "{text}"
    );
}

mod coding;
#[cfg(feature = "debug-hooks")]
mod debug_lines;
mod multi_trace;
mod os_errno;
mod range;
mod read_trace;
mod setup_trace;
mod sigv4;
mod tcp_trace;
mod time_condition;
mod timer_trace;
mod wait_trace;
mod write_trace;

/// `Proxy-Connection:` counts only on a connection through an HTTP
/// proxy (`http_header_p`'s `http_proxy.peer`): a server's says nothing.
#[test]
fn proxy_connection_counts_only_through_a_proxy() {
    let reply: &[u8] =
        b"HTTP/1.1 200 OK\r\nProxy-Connection: close\r\nContent-Length: 3\r\n\r\nok\n";
    let said = "HTTP/1.1 proxy connection set close\n".to_string();
    for proxied in [false, true] {
        let (mut m, talk, _) = server(&[reply], false);
        let ran = get(&mut m, "/", talk, |o| {
            if proxied {
                o.set_url(Some(b"http://origin.example/")).unwrap();
                o.proxy.make_mut().unwrap().url = Some(format!("127.0.0.1:{PORT}").into_bytes());
            }
        });
        assert_eq!(ran.result, Ok(()));
        let text = ran.seen.text();
        assert_eq!(text.contains(&said), proxied, "{text:?}");
        let left = format!("Connection #0 to host 127.0.0.1:{PORT} left intact\n");
        assert_eq!(text.contains(&left), !proxied, "{text:?}");
    }
}

/// A 401 reads only `WWW-Authenticate:` for the server's methods: a
/// `Proxy-Authenticate:` beside it offers nothing to answer.
#[test]
fn a_401_reads_no_proxy_challenge() {
    let reply: &[u8] =
        b"HTTP/1.1 401 Who\r\nProxy-Authenticate: Basic realm=\"p\"\r\nContent-Length: 0\r\n\r\n";
    let (mut m, talk, _) = server(&[reply, OK], false);
    let ran = get(&mut m, "/a", talk, |o| {
        *o.login.make_mut().unwrap() = crate::options::Login::from_pair(b"u:p").unwrap();
        o.http.auth = crate::options::HttpAuth(AuthMethods::ANY);
    });
    assert_eq!(ran.result, Ok(()));
    let text = String::from_utf8_lossy(&ran.request).into_owned();
    assert_eq!(text.matches("GET /a ").count(), 1, "{text}");
    assert_eq!(ran.easy.report().auth_offered(), AuthMethods::NONE);
}

/// A challenge offering no method the request can use leaves the method
/// it used as the one used (`Curl_http_auth_act` sets the picked one only
/// when it picks), for the server and for a proxy alike.
#[test]
fn a_challenge_with_nothing_to_pick_keeps_the_method_used() {
    let host: &[u8] =
        b"HTTP/1.1 401 Who\r\nWWW-Authenticate: X-Other realm=\"a\"\r\nContent-Length: 0\r\n\r\n";
    let (mut m, talk, _) = server(&[host], false);
    let ran = get(&mut m, "/a", talk, |o| {
        *o.login.make_mut().unwrap() = crate::options::Login::from_pair(b"u:p").unwrap();
    });
    assert_eq!(ran.result, Ok(()));
    assert_eq!(ran.easy.report().auth_used(), AuthMethods::BASIC);
    let proxy: &[u8] =
        b"HTTP/1.1 407 Who\r\nProxy-Authenticate: X-Other realm=\"a\"\r\nContent-Length: 0\r\n\r\n";
    let (mut m, talk, _) = server(&[proxy], false);
    let ran = get(&mut m, "/", talk, |o| {
        o.set_url(Some(b"http://origin.example/a")).unwrap();
        o.proxy.make_mut().unwrap().url = Some(format!("127.0.0.1:{PORT}").into_bytes());
        o.proxy.make_mut().unwrap().user = Some(b"u".to_vec());
        o.proxy.make_mut().unwrap().password = Some(b"p".to_vec());
    });
    assert_eq!(ran.result, Ok(()));
    assert_eq!(ran.easy.report().proxy_auth_used(), AuthMethods::BASIC);
}

/// A proxy that refuses the connection is named in the failure, after
/// the origin asked for, as the C build says it.
#[test]
fn a_refusing_proxy_is_named_in_the_failure() {
    let mut m = serving(Peer::Refuses, &[]);
    let ran = get(&mut m, "/", Conversation::replies(&[], false), tunneled);
    assert_eq!(ran.result, Err(ErrorKind::CouldntConnect));
    let said = "Failed to connect to origin.example:80 over proxy 127.0.0.1 after 0 ms: \
                Could not connect to server\n";
    assert!(
        ran.seen.text().iter().any(|l| l == said),
        "{:?}",
        ran.seen.text()
    );
}

/// The report has the response's media type and the connection's ends,
/// and says no proxy was used for a transfer that went direct.
#[test]
fn the_report_has_the_media_type_and_the_ends() {
    let reply: &[u8] =
        b"HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=x\r\nContent-Length: 3\r\n\r\nok\n";
    let ran = run("/", reply, false, |_| {});
    assert_eq!(ran.result, Ok(()));
    let report = ran.easy.report();
    assert_eq!(report.content_type(), Some(&b"text/html; charset=x"[..]));
    let ends = report.primary().expect("the connection's ends");
    assert_eq!(ends.remote, SocketAddr::from(([127, 0, 0, 1], PORT)));
    assert!(ends.local.is_some());
    assert!(!report.used_proxy());
}

/// A list naming `example.com` alone as a public suffix.
struct ExampleIsPublic;

impl crate::cookie::PublicSuffixes for ExampleIsPublic {
    fn is_public_suffix(&self, domain: &[u8]) -> bool {
        domain == b"example.com"
    }

    fn accepts(&self, host: &[u8], domain: &[u8]) -> bool {
        !self.is_public_suffix(domain) || host == domain
    }
}

fn example_is_public() -> Result<crate::cookie::Suffixes, curl_alloc::OutOfMemory> {
    crate::cookie::Suffixes::new(Box::new(ExampleIsPublic))
}

/// The handle's public suffixes, given or made when first wanted, keep a
/// server from setting a cookie for a suffix; without them it may.
#[test]
fn a_handle_s_public_suffixes_refuse_cookies_for_a_suffix() {
    let reply: &[u8] =
        b"HTTP/1.1 200 OK\r\nSet-Cookie: a=1; domain=example.com\r\nContent-Length: 0\r\n\r\n";
    for list in ["none", "given", "made"] {
        let mut e = Easy::new();
        match list {
            "given" => e.set_public_suffixes(Some(example_is_public().unwrap())),
            "made" => e.set_public_suffixes_from(example_is_public),
            _ => e.set_public_suffixes(None),
        }
        let (mut m, talk, _) = server(&[reply], false);
        let mut ran = get_with(&mut m, e, "/", talk, |o| {
            o.http.headers = UserHeaders::new([&b"Host: www.example.com"[..]]).unwrap();
            o.http.cookies.make_mut().unwrap().files.push(b"").unwrap();
        });
        assert_eq!(ran.result, Ok(()));
        let kept = ran.easy.cookie_list().unwrap();
        assert_eq!(kept.is_empty(), list != "none", "{list}: {kept:?}");
    }
}

/// An idle connection a share keeps, whose peer has closed, is found dead
/// by the next transfer looking for one, which connects anew.
#[test]
fn a_share_s_dead_connection_is_not_reused() {
    use crate::share::{Kind, Share};
    let first = Conversation::replies(&[OK], true);
    let second = Conversation::replies(&[OK], false);
    let mut m = serving(Peer::Accepts, &[&first, &second]);
    let share = Share::new().unwrap();
    share.keep(Kind::Connections).unwrap();
    let mut e = Easy::new();
    e.set_share(Some(share.clone()));
    let ran = get_with(&mut m, e, "/", first, |_| {});
    assert_eq!(ran.result, Ok(()));
    let mut e = Easy::new();
    e.set_share(Some(share.clone()));
    let ran = get_with(&mut m, e, "/", second.clone(), |_| {});
    assert_eq!(ran.result, Ok(()));
    let said = "Connection 0 seems to be dead, terminating\n".to_string();
    assert!(ran.seen.text().contains(&said), "{:?}", ran.seen.text());
    assert_eq!(ran.easy.report().connects(), 1);
    assert_eq!(second.received(), request_of("/"));
}

/// A connection whose SOCKS5 proxy did not authenticate the user serves
/// a transfer that does not insist it must (`url_match_proxy_use`).
#[test]
fn an_unauthenticated_socks5_connection_serves_a_transfer_not_insisting() {
    let talk = Conversation::replies(&[b"\x05\x00", SOCKS5_GRANTED, OK, OK], false).per_send();
    let mut m = serving(Peer::Accepts, &[&talk]);
    let through = |o: &mut Options| through_socks(o, "socks5h", b"http://origin.example/a");
    let ran = get(&mut m, "/", talk.clone(), through);
    assert_eq!(ran.result, Ok(()));
    let ran = get_with(&mut m, ran.easy, "/", talk.clone(), through);
    assert_eq!(ran.result, Ok(()));
    assert_eq!(ran.easy.report().connects(), 0, "reused");
}

/// The proxy variables a child run of this binary is given; nothing else
/// of the kind reaches it.
const PROXY_VARIABLES: [&str; 8] = [
    "http_proxy",
    "HTTP_PROXY",
    "https_proxy",
    "HTTPS_PROXY",
    "all_proxy",
    "ALL_PROXY",
    "no_proxy",
    "NO_PROXY",
];

/// Run the test `name` of this binary in a child process, with `mode` in
/// `CURL_CORE_CHILD` and the proxy variables `env` alone set: the
/// environment is the whole process's, so it is set in a child of its
/// own, and the child must have run the one test and passed it.
fn in_child(name: &str, mode: &str, env: &[(&str, &str)]) {
    let mut child = std::process::Command::new(std::env::current_exe().unwrap());
    child
        .args(["--exact", name, "--test-threads=1"])
        .env("CURL_CORE_CHILD", mode);
    for v in PROXY_VARIABLES {
        child.env_remove(v);
    }
    for (k, v) in env {
        child.env(k, v);
    }
    let out = child.output().unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success() && stdout.contains("1 passed"),
        "{mode}: {stdout}{}",
        String::from_utf8_lossy(&out.stderr)
    );
}

/// The environment names the proxy where the options name none, traced
/// as C traces it; an empty proxy or pre-proxy in the options turns it
/// off; and the environment's no-proxy list, in capitals too, keeps a
/// host from it (`Curl_proxy_init_conn`, `detect_proxy`).
#[test]
fn the_environment_names_a_proxy() {
    let proxy = format!("http://127.0.0.1:{PORT}");
    in_child(
        "proto::http::tests::proxy_from_the_environment",
        "detect",
        &[("http_proxy", &proxy)],
    );
    in_child(
        "proto::http::tests::proxy_from_the_environment",
        "exclude",
        &[("http_proxy", &proxy), ("NO_PROXY", "127.0.0.1")],
    );
}

/// The child half of `the_environment_names_a_proxy`; nothing outside a
/// child run.
#[test]
fn proxy_from_the_environment() {
    let Some(mode) = std::env::var_os("CURL_CORE_CHILD") else {
        return;
    };
    let fetch = |url: &[u8], set: fn(&mut Options)| {
        let (mut m, talk, _) = server(&[OK], false);
        let ran = get(&mut m, "/", talk, |o| {
            o.set_url(Some(url)).unwrap();
            set(o);
        });
        assert_eq!(ran.result, Ok(()));
        let (line, _) = first_line(&ran.request);
        (line, ran.seen.text())
    };
    let direct = format!("http://127.0.0.1:{PORT}/");
    if mode == "detect" {
        let (line, said) = fetch(b"http://origin.example/a", |_| {});
        assert_eq!(line, "GET http://origin.example/a HTTP/1.1\r\n");
        let uses = format!("Uses proxy env variable http_proxy == 'http://127.0.0.1:{PORT}'\n");
        assert!(said.contains(&uses), "{said:?}");
        let off: [fn(&mut Options); 2] = [
            |o| o.proxy.make_mut().unwrap().url = Some(Vec::new()),
            |o| o.proxy.make_mut().unwrap().pre_proxy = Some(Vec::new()),
        ];
        for set in off {
            let (line, said) = fetch(direct.as_bytes(), set);
            assert_eq!(line, "GET / HTTP/1.1\r\n");
            assert!(
                !said.iter().any(|l| l.starts_with("Uses proxy")),
                "{said:?}"
            );
        }
    } else {
        let (line, said) = fetch(direct.as_bytes(), |_| {});
        assert_eq!(line, "GET / HTTP/1.1\r\n", "not through the proxy");
        let uses = "Uses proxy env variable NO_PROXY == '127.0.0.1'\n".to_string();
        assert!(said.contains(&uses), "{said:?}");
    }
}

/// A request whose head cannot be sent over a reused connection, its
/// peer gone, is made again on a fresh one; over a fresh one, the failure
/// is the transfer's (`multistate_do` retries a reused connection alone).
#[test]
fn a_send_failing_on_a_reused_connection_is_made_again() {
    let first = Conversation::replies(&[OK], false).breaking_after(1);
    let second = Conversation::replies(&[OK], false);
    let mut m = serving(Peer::Accepts, &[&first, &second]);
    let ran = get(&mut m, "/", first.clone(), |_| {});
    assert_eq!(ran.result, Ok(()));
    let ran = get_with(&mut m, ran.easy, "/", second.clone(), |_| {});
    assert_eq!(ran.result, Ok(()));
    assert_eq!(second.received(), request_of("/"));
    let fresh = Conversation::replies(&[OK], false).breaking_after(0);
    let spare = Conversation::replies(&[OK], false);
    let mut m = serving(Peer::Accepts, &[&fresh, &spare]);
    let ran = get(&mut m, "/", fresh, |_| {});
    assert_eq!(ran.result, Err(ErrorKind::SendError));
    assert!(spare.received().is_empty(), "not made again");
}

/// Digest's client nonce is random: never the encoding of zero bytes,
/// and another for each handle.
#[test]
fn a_digest_client_nonce_is_random() {
    let challenge: &[u8] = b"HTTP/1.1 401 Who\r\n\
        WWW-Authenticate: Digest realm=\"r\", nonce=\"n\", qop=\"auth\"\r\nContent-Length: 0\r\n\r\n";
    let cnonce = || {
        let (mut m, talk, _) = server(&[challenge, OK], false);
        let ran = get(&mut m, "/", talk, |o| {
            *o.login.make_mut().unwrap() = crate::options::Login::from_pair(b"u:p").unwrap();
            o.http.auth = crate::options::HttpAuth(AuthMethods::DIGEST);
        });
        assert_eq!(ran.result, Ok(()));
        let text = String::from_utf8_lossy(&ran.request).into_owned();
        let at = text.find("cnonce=\"").expect("a client nonce") + 8;
        let len = text[at..].find('"').unwrap();
        text[at..at + len].to_string()
    };
    let (one, two) = (cnonce(), cnonce());
    assert_ne!(one, "AAAAAAAAAAAAAAAA");
    assert_ne!(one, two);
}

/// Only a 100 releases a body held for one: another interim response
/// leaves it held until the wait runs out (`http_on_1xx_response`).
#[test]
fn only_a_100_releases_a_held_body() {
    let processing = [&b"HTTP/1.1 102 Processing\r\n\r\n"[..], OK_EMPTY].concat();
    let (ran, waited) = expecting(&processing, b"a=b", |o| {
        o.http.headers = UserHeaders::new([&b"Expect: 100-continue"[..]]).unwrap();
        o.http.continue_wait = crate::options::ContinueWait(Duration::from_millis(300));
    });
    assert_eq!((ran.result, waited), (Ok(()), Duration::from_millis(300)));
    assert!(ran.request.ends_with(b"\r\n\r\na=b"));
}

/// A 417 after the 100, before any of the body went, is one while
/// sending, not while waiting: the connection closes and the request is
/// made again without `Expect` (`http_handle_send_error`).
#[test]
fn a_417_after_the_100_is_one_while_sending() {
    let refused = [
        &b"HTTP/1.1 100 Continue\r\n\r\n"[..],
        b"HTTP/1.1 417 Nope\r\nContent-Length: 0\r\n\r\n",
    ]
    .concat();
    let first = Conversation::replies(&[&refused], false);
    let second = Conversation::replies(&[OK_EMPTY], false);
    let mut m = serving(Peer::Accepts, &[&first, &second]);
    let ran = get(&mut m, "/p", first, |o| {
        o.method = Method::Post;
        o.upload = UploadSource::Bytes(curl_alloc::TryArc::try_new(b"a=b".to_vec()).unwrap());
        o.http.headers = UserHeaders::new([&b"Expect: 100-continue"[..]]).unwrap();
    });
    assert_eq!(ran.result, Ok(()));
    let said = "Got HTTP failure 417 while sending data\n".to_string();
    assert!(ran.seen.text().contains(&said), "{:?}", ran.seen.text());
    assert_eq!(ran.easy.report().connects(), 2);
}

/// An error response heard while the body goes stops it, saying how much
/// went (`req_set_upload_done`).
#[test]
fn an_upload_stopped_says_how_much_went() {
    const SIZE: usize = 300_000;
    let not_found = b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n";
    let talk = Conversation::replies(&[not_found], false);
    let mut m = serving(Peer::Accepts, &[&talk]);
    let stream = Stream::new(big_body(SIZE));
    let ran = get(&mut m, "/a", talk.clone(), |o| {
        o.method = Method::Upload;
        o.upload = stream.source(false);
    });
    assert_eq!(ran.result, Ok(()));
    let went = after_head(&talk.received());
    assert!(went > 0 && went < SIZE);
    let said = format!("abort upload after having sent {went} bytes\n");
    assert!(ran.seen.text().contains(&said), "{:?}", ran.seen.text());
}

/// An empty body sent says the request went, not that an upload did
/// (`req_set_upload_done`, a total length of zero).
#[test]
fn an_empty_body_says_the_request_went() {
    let (mut m, talk, _) = server(&[OK_EMPTY], false);
    let ran = get(&mut m, "/p", talk, |o| {
        o.method = Method::Post;
        o.upload = UploadSource::Bytes(curl_alloc::TryArc::try_new(Vec::new()).unwrap());
    });
    assert_eq!(ran.result, Ok(()));
    let said = "Request completely sent off\n".to_string();
    assert!(ran.seen.text().contains(&said), "{:?}", ran.seen.text());
}

/// An error response that stops the body waiting for a 100 stops the
/// wait's timer with it (`cr_exp100_done`): with the rest of the response
/// still to come, nothing is due.
#[test]
fn a_body_stopped_while_awaiting_a_100_stops_its_timer() {
    let (mut m, _talk, _) = server(&[b"HTTP/1.1 404 Nope\r\nContent-Length: 5\r\n\r\n"], false);
    let mut e = Easy::new();
    let o = e.options_mut();
    o.set_url(Some(format!("http://127.0.0.1:{PORT}/p").as_bytes()))
        .unwrap();
    o.method = Method::Post;
    o.upload = UploadSource::Bytes(curl_alloc::TryArc::try_new(b"a=b".to_vec()).unwrap());
    o.http.headers = UserHeaders::new([&b"Expect: 100-continue"[..]]).unwrap();
    m.add(Box::new(e), (), &mut NoEvents).unwrap();
    for _ in 0..5 {
        m.perform(&mut NoEvents).unwrap();
    }
    assert!(m.info_read().is_none(), "the body is still to come");
    assert_eq!(m.timeout(), None);
}

/// A head that fills the request's buffer leaves its body to the passes
/// after it, read into the buffer as the head goes.
#[test]
fn a_head_filling_the_buffer_sends_the_body_after_it() {
    let (mut m, talk, _) = server(&[OK_EMPTY], false);
    let big = format!("X-Big: {}", "b".repeat(70_000));
    let ran = get(&mut m, "/p", talk, |o| {
        o.method = Method::Post;
        o.upload = UploadSource::Bytes(curl_alloc::TryArc::try_new(b"a=b".to_vec()).unwrap());
        o.http.headers = UserHeaders::new([big.as_bytes()]).unwrap();
    });
    assert_eq!(ran.result, Ok(()));
    assert!(ran.request.ends_with(b"\r\n\r\na=b"));
}

/// A body all sent leaves nothing to send, whatever its size: a
/// redirect after it has no reason to close the connection
/// (`http_perhapsrewind` once `Curl_req_done_sending`).
#[test]
fn a_body_all_sent_has_nothing_left() {
    use crate::proto::http1::framing::Left;
    let source = UploadSource::Read {
        handler: Handler::read(Stream::new(b"x")).unwrap(),
        rewind: None,
        size: None,
    };
    let body = crate::upload::chain::Body::new(crate::upload::Upload::plain(&source));
    let left = |sent_all| super::Request::left_to_send(Some(&body), sent_all, 1).left;
    assert_eq!(left(true), Left::Nothing);
    assert_eq!(left(false), Left::Unknown);
}

/// A body sent chunked has no size left to weigh, though the
/// application gave one: the C build says "close instead of sending
/// unknown amount of more bytes" for a 307 in the middle of one.
#[test]
fn a_chunked_body_has_an_unknown_amount_left() {
    use crate::proto::http1::framing::Left;
    let stream = Stream::new(b"0123456789");
    let mut body =
        crate::upload::chain::Body::new(crate::upload::Upload::plain(&stream.source(false)));
    assert_eq!(
        super::Request::left_to_send(Some(&body), false, 4).left,
        Left::Bytes(6)
    );
    body.chunked().unwrap();
    assert_eq!(
        super::Request::left_to_send(Some(&body), false, 4).left,
        Left::Unknown
    );
}

/// A redirect's body is weighed once, as its `Location:` is read
/// (`http_header_l`): wherever the field is in the head, and however many
/// fields follow it.
#[test]
fn a_redirect_weighs_the_body_once_at_its_location() {
    for reply in [
        &b"HTTP/1.1 307 Moved\r\nContent-Length: 0\r\nLocation: /b\r\n\r\n"[..],
        b"HTTP/1.1 307 Moved\r\nLocation: /b\r\nA: 1\r\nContent-Length: 0\r\n\r\n",
    ] {
        let (mut m, talk, _) = server(&[reply, OK], false);
        let stream = Stream::new(b"body");
        let ran = get(&mut m, "/a", talk, |o| {
            o.method = Method::Upload;
            o.upload = stream.source(true);
            o.http.follow = Follow::All;
        });
        assert_eq!(ran.result, Ok(()));
        let need = "Need to rewind upload for next request\n".to_string();
        let said = ran.seen.text().iter().filter(|l| **l == need).count();
        assert_eq!(said, 1, "{:?}", ran.seen.text());
        assert_eq!(stream.rewinds.get(), 1);
    }
}

/// A location without a scheme keeps the port the application applies,
/// though it names a host: the C build follows `//127.0.0.1/b` on the
/// applied port too, its URL showing none.
#[test]
fn a_location_without_a_scheme_keeps_the_applied_port() {
    let (mut m, talk, _) = server(&[&redirect(301, "//127.0.0.1/b"), OK], false);
    let ran = get(&mut m, "/a", talk, |o| {
        o.set_url(Some(b"http://127.0.0.1:1/a")).unwrap();
        o.port = std::num::NonZeroU16::new(PORT);
        o.http.follow = Follow::All;
    });
    assert_eq!(ran.result, Ok(()));
    let said = "Issue another request to this URL: 'http://127.0.0.1/b'\n".to_string();
    assert!(ran.seen.text().contains(&said), "{:?}", ran.seen.text());
    assert!(second_request(&ran).starts_with("GET /b HTTP/1.1\r\n"));
}

/// A head with no size: the body lasts until the connection closes.
const UNTIL_CLOSE: &[u8] = b"HTTP/1.1 200 OK\r\n\r\n";

/// Counts the body's bytes and drops them.
#[derive(Clone, Default)]
struct Drops(Arc<crate::test_cell::Cell<u64>>);

impl WriteHandler for Drops {
    fn write(&self, _: &mut TransferCx<'_>, body: &[u8]) -> Write {
        self.0.set(self.0.get() + body.len() as u64);
        Write::Accepted
    }
}

/// A multi whose server at `PORT` answers each connection with a head
/// and then a body without end, each read of it taking a millisecond;
/// one conversation for each of `connections`.
fn endless(connections: usize) -> (Multi, Vec<Conversation>) {
    let (m, talks, _) = endless_clocked(connections);
    (m, talks)
}

/// `endless`, with the multi's clock.
fn endless_clocked(connections: usize) -> (Multi, Vec<Conversation>, ManualClock) {
    let clock = ManualClock::new().unwrap();
    let at = SocketAddr::from(([127, 0, 0, 1], PORT));
    let mut net = FakeNet::new(clock.clone()).with_peer(at, Peer::Accepts);
    let mut talks = Vec::new();
    for _ in 0..connections {
        let talk = Conversation::new(UNTIL_CLOSE, false).endless(Duration::from_millis(1));
        net = net.with_conversation(at, talk.clone());
        talks.push(talk);
    }
    let env = Env {
        clock: Box::new(clock.clone()),
        net: Box::new(net),
        arena: ArenaPolicy::new(16, 0).unwrap(),
        waker: None,
    };
    (Multi::new(env).unwrap(), talks, clock)
}

/// A GET whose body is dropped, counted in the `Drops`, with the options
/// `set` makes.
fn endless_get(set: impl FnOnce(&mut Options)) -> (Easy, Drops) {
    let mut e = Easy::new();
    let drops = Drops::default();
    let o = e.options_mut();
    let url = format!("http://127.0.0.1:{PORT}/");
    o.set_url(Some(url.as_bytes())).unwrap();
    o.callbacks.write = Some(Handler::write(drops.clone()).unwrap());
    set(o);
    (e, drops)
}

/// A step reads at most eleven times, and one that stops with more
/// perhaps to read is run again at once, not when its socket is next
/// ready (`sendrecv_dl`: `maxloops` and `Curl_multi_mark_dirty`).
#[test]
fn a_step_reads_eleven_times_at_most_and_runs_again_at_once() {
    let (mut m, talks) = endless(1);
    let (e, drops) = endless_get(|_| {});
    m.add(Box::new(e), (), &mut NoEvents).unwrap();
    while talks[0].endless_reads() == 0 {
        m.perform(&mut NoEvents).unwrap();
    }
    for _ in 0..3 {
        let (reads, got) = (talks[0].endless_reads(), drops.0.get());
        m.perform(&mut NoEvents).unwrap();
        assert_eq!(talks[0].endless_reads() - reads, 11);
        assert_eq!(drops.0.get() - got, 11 * 16384);
        assert_eq!(m.timeout(), Some(Duration::ZERO));
    }
}

/// A read takes no more than the buffer's size (`CURLOPT_BUFFERSIZE`).
#[test]
fn a_read_takes_the_buffer_s_size() {
    let (mut m, talks) = endless(1);
    let (e, drops) = endless_get(|o| o.limits.buffer_size = BufferSize::clamped(4000));
    m.add(Box::new(e), (), &mut NoEvents).unwrap();
    while talks[0].endless_reads() == 0 {
        m.perform(&mut NoEvents).unwrap();
    }
    let (reads, got) = (talks[0].endless_reads(), drops.0.get());
    m.perform(&mut NoEvents).unwrap();
    assert_eq!(talks[0].endless_reads() - reads, 11);
    assert_eq!(drops.0.get() - got, 11 * 4000);
}

/// A body that never ends, from a peer faster than its reader, still
/// ends at the total time limit (C ends test 3237's the same way).
#[test]
fn an_endless_body_ends_at_the_time_limit() {
    let (mut m, talks) = endless(1);
    let seen = Seen::default();
    let (e, drops) = endless_get(|o| {
        o.limits.total = crate::time::TimeLimit::from_millis(1000);
        o.output.verbose = true;
        o.callbacks.debug = Some(Handler::debug(seen.clone()).unwrap());
    });
    let id = m.add(Box::new(e), (), &mut NoEvents).unwrap();
    let result = drive_to_completion(&mut m, id, &mut NoEvents).unwrap();
    assert_eq!(result, Err(ErrorKind::OperationTimedout));
    let text = seen.text();
    let said = text
        .iter()
        .find(|l| l.starts_with("Operation timed out after "))
        .unwrap_or_else(|| panic!("{text:?}"));
    let after: u64 = said
        .strip_prefix("Operation timed out after ")
        .and_then(|s| s.split(' ').next())
        .and_then(|n| n.parse().ok())
        .unwrap_or_else(|| panic!("{said:?}"));
    // Late by no more than one step's reads.
    assert!((1000..=1011).contains(&after), "{said:?}");
    let bytes = drops.0.get();
    assert!(
        said.ends_with(&format!(" with {bytes} bytes received\n")),
        "{said:?}"
    );
    assert!(talks[0].endless_reads() <= 1011);
}

/// The progress handler runs while a body faster than its reader comes,
/// and can abort it.
#[test]
fn a_progress_abort_stops_an_endless_body() {
    let (mut m, _talks) = endless(1);
    let aborts = AbortsAt {
        calls: Arc::default(),
        abort_at: 5,
    };
    let progress = aborts.clone();
    let (e, _) = endless_get(move |o| {
        o.progress = crate::options::Progress::Handler(Handler::progress(progress).unwrap());
    });
    let id = m.add(Box::new(e), (), &mut NoEvents).unwrap();
    let result = drive_to_completion(&mut m, id, &mut NoEvents).unwrap();
    assert_eq!(result, Err(ErrorKind::AbortedByCallback));
    assert_eq!(aborts.calls.get(), 5);
}

/// Two transfers each with a body faster than its reader both move on
/// in every pass: neither starves the other.
#[test]
fn transfers_with_endless_bodies_take_turns() {
    let (mut m, talks) = endless(2);
    let (one, one_got) = endless_get(|_| {});
    let (two, two_got) = endless_get(|_| {});
    m.add(Box::new(one), (), &mut NoEvents).unwrap();
    m.add(Box::new(two), (), &mut NoEvents).unwrap();
    while talks.iter().any(|t| t.endless_reads() == 0) {
        m.perform(&mut NoEvents).unwrap();
    }
    for _ in 0..3 {
        let reads: Vec<usize> = talks.iter().map(Conversation::endless_reads).collect();
        let got = (one_got.0.get(), two_got.0.get());
        m.perform(&mut NoEvents).unwrap();
        for (talk, before) in talks.iter().zip(reads) {
            assert_eq!(talk.endless_reads() - before, 11);
        }
        assert!(one_got.0.get() > got.0 && two_got.0.get() > got.1);
    }
}

/// The receive limit's rate, above a read's 16 KiB: each step's tokens
/// are read in that step's pass, in reads the tokens cut short.
const RECV_RATE: u64 = 50_000;

/// Perform until the transfer's body has started to come.
fn until_body(m: &mut Multi, drops: &Drops) {
    for _ in 0..100 {
        if drops.0.get() > 0 {
            return;
        }
        m.perform(&mut NoEvents).unwrap();
    }
    panic!("no body came");
}

/// Under a receive limit, a body from a peer faster than its reader comes
/// at the limit's rate, a step's worth at a time, the transfer waiting out
/// each step on its timer without reading (`Curl_rlimit_*`,
/// `mspeed_check`, RATELIMITING). Untuned, as its size is unknown, a step
/// is a second: its tokens come when it ends, the wait is what is left of
/// it, rounded up to a millisecond.
#[test]
fn a_receive_limit_lets_its_rate_through_each_second() {
    let (mut m, talks, clock) = endless_clocked(1);
    let (e, drops) =
        endless_get(|o| o.flow.make_mut().unwrap().max_recv_speed = NonZeroU64::new(RECV_RATE));
    m.add(Box::new(e), (), &mut NoEvents).unwrap();
    until_body(&mut m, &drops);
    // The first step's tokens all came in the pass that started the body:
    // three reads of 16384 and one of what was left.
    assert_eq!(drops.0.get(), RECV_RATE);
    let start = clock.now();
    for second in 1..=3 {
        // Waiting out the step, on its timer alone: no socket
        // (RATELIMITING has no pollset).
        let mut sockets = 0;
        m.sockets(&mut NoEvents, |_, _| sockets += 1);
        assert_eq!(sockets, 0, "second {second}");
        let wait = m.timeout().expect("a timer for the limit");
        // The pass's reads moved the clock on 4 ms since the step began.
        assert_eq!(wait, Duration::from_millis(1000 - 4), "second {second}");
        let reads = talks[0].endless_reads();
        // Nothing is read before the timer.
        clock.advance(wait - Duration::from_millis(1));
        m.perform(&mut NoEvents).unwrap();
        assert_eq!(talks[0].endless_reads(), reads);
        clock.advance(Duration::from_millis(1));
        m.perform(&mut NoEvents).unwrap();
        assert_eq!(drops.0.get(), RECV_RATE * (second + 1), "second {second}");
        assert_eq!(talks[0].endless_reads() - reads, 4);
    }
    assert_eq!(clock.now().since(start), Duration::from_millis(3 * 1000));
}

/// A body of a known size is spread so its last step is small: 120000
/// bytes at 50000 a second go as 59400 in each of two steps of 1188 ms,
/// then the last 1200 (`rlimit_tune_steps`: a hundredth for the last
/// step, the rest's 2376 ms spread over two steps).
#[test]
fn a_receive_limit_spreads_a_known_size() {
    let size = 120_000;
    let head = format!("HTTP/1.1 200 OK\r\nContent-Length: {size}\r\n\r\n");
    let clock = ManualClock::new().unwrap();
    let at = SocketAddr::from(([127, 0, 0, 1], PORT));
    let talk = Conversation::new(head.as_bytes(), false).endless(Duration::from_millis(1));
    let net = FakeNet::new(clock.clone())
        .with_peer(at, Peer::Accepts)
        .with_conversation(at, talk.clone());
    let env = Env {
        clock: Box::new(clock.clone()),
        net: Box::new(net),
        arena: ArenaPolicy::new(16, 0).unwrap(),
        waker: None,
    };
    let mut m: Multi = Multi::new(env).unwrap();
    let (e, drops) =
        endless_get(|o| o.flow.make_mut().unwrap().max_recv_speed = NonZeroU64::new(RECV_RATE));
    let id = m.add(Box::new(e), (), &mut NoEvents).unwrap();
    until_body(&mut m, &drops);
    assert_eq!(drops.0.get(), 59_400);
    // Four reads moved the clock 4 ms into the 1188 ms step.
    assert_eq!(m.timeout(), Some(Duration::from_millis(1188 - 4)));
    clock.advance(Duration::from_millis(1188 - 4));
    m.perform(&mut NoEvents).unwrap();
    assert_eq!(drops.0.get(), 2 * 59_400);
    assert_eq!(m.timeout(), Some(Duration::from_millis(1188 - 4)));
    clock.advance(Duration::from_millis(1188 - 4));
    let result = drive_to_completion(&mut m, id, &mut NoEvents).unwrap();
    assert_eq!(result, Ok(()));
    assert_eq!(drops.0.get(), size);
}

/// A pause stops the limit, and going on starts it over, with a step's
/// tokens at once and nothing earned while paused (`Curl_rlimit_block`).
#[test]
fn an_unpause_starts_the_receive_limit_over() {
    let (mut m, _talks, clock) = endless_clocked(1);
    let (e, drops) =
        endless_get(|o| o.flow.make_mut().unwrap().max_recv_speed = NonZeroU64::new(RECV_RATE));
    let id = m.add(Box::new(e), (), &mut NoEvents).unwrap();
    until_body(&mut m, &drops);
    assert_eq!(drops.0.get(), RECV_RATE);
    clock.advance(Duration::from_millis(300));
    m.pause(id, PauseRequest::RECV, &mut NoEvents).unwrap();
    m.perform(&mut NoEvents).unwrap();
    clock.advance(Duration::from_secs(5));
    m.perform(&mut NoEvents).unwrap();
    assert_eq!(drops.0.get(), RECV_RATE);
    m.pause(id, PauseRequest::CONT, &mut NoEvents).unwrap();
    m.perform(&mut NoEvents).unwrap();
    // A step's tokens, not six seconds' worth (nor the burst's).
    assert_eq!(drops.0.get(), 2 * RECV_RATE);
    assert_eq!(m.timeout(), Some(Duration::from_millis(1000 - 4)));
}

/// A transfer whose time runs out as it waits for the response fails as
/// the next pass starts, reading nothing more (`multi_handle_timeout`
/// ahead of `Curl_sendrecv`): its one receive is the one before it first
/// waited.
#[test]
fn a_transfer_out_of_time_reads_no_more() {
    let clock = ManualClock::new().unwrap();
    let at = SocketAddr::from(([127, 0, 0, 1], PORT));
    // A peer that never answers.
    let talk = Conversation::replies(&[], false);
    let net = FakeNet::new(clock.clone())
        .with_peer(at, Peer::Accepts)
        .with_conversation(at, talk);
    let env = Env {
        clock: Box::new(clock.clone()),
        net: Box::new(net),
        arena: ArenaPolicy::new(16, 0).unwrap(),
        waker: None,
    };
    let mut m: Multi = Multi::new(env).unwrap();
    let seen = Seen::default();
    let mut e = Easy::new();
    let components = crate::components::Components::new().unwrap();
    components.configure(b"tcp");
    e.set_components(Some(components));
    let o = e.options_mut();
    o.set_url(Some(format!("http://127.0.0.1:{PORT}/").as_bytes()))
        .unwrap();
    o.limits.total = crate::time::TimeLimit::from_millis(1000);
    o.output.verbose = true;
    o.callbacks.debug = Some(Handler::debug(seen.clone()).unwrap());
    let id = m.add(Box::new(e), (), &mut NoEvents).unwrap();
    let result = drive_to_completion(&mut m, id, &mut NoEvents).unwrap();
    assert_eq!(result, Err(ErrorKind::OperationTimedout));
    let text = seen.text();
    let recvs = text.iter().filter(|l| l.starts_with("[TCP] recv(")).count();
    assert_eq!(recvs, 1, "{text:?}");
    assert!(
        text.iter()
            .any(|l| l.starts_with("Operation timed out after 1000 milliseconds")),
        "{text:?}"
    );
}

/// Only the debug build says what C's debug build alone traces: a
/// plain build's request, body, end and failure say none of it.
#[cfg(not(feature = "debug-hooks"))]
#[test]
fn the_plain_build_says_no_debug_lines() {
    let (mut m, talk, _) = server(&[UNTIL_CLOSE], true);
    let ran = get(&mut m, "/p", talk, |o| {
        o.method = Method::Post;
        o.upload = UploadSource::Bytes(curl_alloc::TryArc::try_new(b"a=b".to_vec()).unwrap());
        o.http.headers = UserHeaders::new([&b"Expect: 100-continue"[..]]).unwrap();
    });
    assert_eq!(ran.result, Ok(()));
    let cut = b"HTTP/1.1 200 OK\r\nContent-Length: 6\r\nFunny-head: swsclose\r\n";
    let ran_cut = run("/", cut, true, |_| {});
    assert_eq!(ran_cut.result, Err(ErrorKind::PartialFile));
    for ran in [&ran, &ran_cut] {
        let text = ran.seen.of("text");
        assert!(text.iter().any(|l| l.starts_with(b"using HTTP/1.x")));
        assert!(
            !text.iter().any(|l| crate::trace::debug_only(l)),
            "{text:?}"
        );
    }
}

/// A transfer waiting out its limit still ends at its time limit.
#[test]
fn a_rate_limited_transfer_times_out() {
    let (mut m, _talks, _clock) = endless_clocked(1);
    let seen = Seen::default();
    let (e, drops) = endless_get(|o| {
        o.flow.make_mut().unwrap().max_recv_speed = NonZeroU64::new(RECV_RATE);
        o.limits.total = crate::time::TimeLimit::from_millis(2500);
        o.output.verbose = true;
        o.callbacks.debug = Some(Handler::debug(seen.clone()).unwrap());
    });
    let id = m.add(Box::new(e), (), &mut NoEvents).unwrap();
    let result = drive_to_completion(&mut m, id, &mut NoEvents).unwrap();
    assert_eq!(result, Err(ErrorKind::OperationTimedout));
    // Three steps' worth, at 0, 1 and 2 seconds.
    assert_eq!(drops.0.get(), 3 * RECV_RATE);
    let text = seen.text();
    assert!(
        text.iter().any(|l| l.starts_with(&format!(
            "Operation timed out after 2500 milliseconds with {} bytes received",
            3 * RECV_RATE
        ))),
        "{text:?}"
    );
}

/// Under a send limit, a body goes at the limit's rate: each step's
/// tokens read and sent at once, then a wait for the next
/// (`Curl_client_read`, `xfer_send`, `mspeed_check`).
#[test]
fn a_send_limit_lets_its_rate_out_each_second() {
    const RATE: u64 = 50_000;
    let clock = ManualClock::new().unwrap();
    let at = SocketAddr::from(([127, 0, 0, 1], PORT));
    // A peer that never answers.
    let talk = Conversation::replies(&[], false);
    let net = FakeNet::new(clock.clone())
        .with_peer(at, Peer::Accepts)
        .with_conversation(at, talk.clone());
    let env = Env {
        clock: Box::new(clock.clone()),
        net: Box::new(net),
        arena: ArenaPolicy::new(16, 0).unwrap(),
        waker: None,
    };
    let mut m: Multi = Multi::new(env).unwrap();
    let mut e = Easy::new();
    let o = e.options_mut();
    o.set_url(Some(format!("http://127.0.0.1:{PORT}/").as_bytes()))
        .unwrap();
    o.method = Method::Post;
    o.upload = UploadSource::Bytes(curl_alloc::TryArc::try_new(vec![b'x'; 200_000]).unwrap());
    o.flow.make_mut().unwrap().max_send_speed = NonZeroU64::new(RATE);
    m.add(Box::new(e), (), &mut NoEvents).unwrap();
    let body = |talk: &Conversation| {
        let got = talk.received();
        let end = got.windows(4).position(|w| w == b"\r\n\r\n").map(|i| i + 4);
        end.map_or(0, |end| got.len() - end) as u64
    };
    for _ in 0..100 {
        m.perform(&mut NoEvents).unwrap();
        if body(&talk) > 0 {
            break;
        }
    }
    assert_eq!(body(&talk), RATE);
    for second in 1..=3u64 {
        let wait = m.timeout().expect("a timer for the limit");
        assert_eq!(wait, Duration::from_millis(1000), "second {second}");
        clock.advance(wait - Duration::from_millis(1));
        m.perform(&mut NoEvents).unwrap();
        assert_eq!(body(&talk), RATE * second);
        clock.advance(Duration::from_millis(1));
        m.perform(&mut NoEvents).unwrap();
        assert_eq!(
            body(&talk),
            (RATE * (second + 1)).min(200_000),
            "second {second}"
        );
    }
}

/// A tree of one part, its boundary all `A`s, and the part.
fn mime_tree(content: crate::mime::Content) -> crate::mime::Mime {
    use crate::mime::{Boundary, Mime, Part};
    let mut m = Mime::new(Boundary::draw(|| Ok::<_, std::convert::Infallible>(0)).unwrap());
    m.add(Part {
        name: Some(b"f".to_vec()),
        content,
        ..Part::default()
    })
    .unwrap();
    m
}

fn mime_source(m: crate::mime::Mime) -> UploadSource {
    let tree = curl_alloc::TryArc::try_new(m).unwrap();
    UploadSource::Mime(Handler::mime(crate::mime::Fixed::new(tree)).unwrap())
}

/// A multipart POST types its head with the tree's boundary after its
/// length, the application's `Content-Type` taken in its place and not
/// sent as given (`http_add_content_hds`, `Curl_add_custom_headers`).
#[test]
fn a_mime_post_types_its_head_with_the_boundary() {
    let tree = mime_tree(crate::mime::Content::Bytes(
        curl_alloc::TryArc::try_new(b"v".to_vec()).unwrap(),
    ));
    let ran = run("/p", OK_EMPTY, false, |o| {
        o.method = Method::Post;
        o.upload = mime_source(tree);
        o.http.headers =
            UserHeaders::new([&b"Content-Type: multipart/related"[..], b"X: 1"]).unwrap();
    });
    assert_eq!(ran.result, Ok(()));
    let line = format!("--------------------------{}", "A".repeat(22));
    let body =
        format!("{line}\r\nContent-Disposition: attachment; name=\"f\"\r\n\r\nv\r\n{line}--\r\n");
    let want = format!(
        "POST /p HTTP/1.1\r\nHost: 127.0.0.1:{PORT}\r\nUser-Agent: curl/test\r\nAccept: */*\r\nX: 1\r\n\
         Content-Length: {}\r\n\
         Content-Type: multipart/related; boundary={}\r\n\r\n{body}",
        body.len(),
        &line[2..],
    );
    assert_eq!(String::from_utf8_lossy(&ran.request), want);
}

/// A probe sends the head lines the last request that sent the tree
/// sent, as C sends the tree's headers as it last made them; before any
/// request has, it sends none (`http_add_content_hds`). Here the first
/// origin's probe sends none, and the probe of the origin it redirects to
/// sends the first origin's.
#[test]
fn a_probe_sends_the_tree_s_head_as_last_sent() {
    let clock = ManualClock::new().unwrap();
    let (a, b) = (
        SocketAddr::from(([127, 0, 0, 1], PORT)),
        SocketAddr::from(([127, 0, 0, 1], PORT + 1)),
    );
    let moved = format!(
        "HTTP/1.1 307 Moved\r\nLocation: http://127.0.0.1:{}/b\r\nContent-Length: 0\r\n\r\n",
        PORT + 1
    );
    let first = Conversation::replies(&[DIGEST_CHALLENGE, moved.as_bytes()], false);
    let second = Conversation::replies(&[DIGEST_CHALLENGE, OK], false);
    let net = FakeNet::new(clock.clone())
        .with_peer(a, Peer::Accepts)
        .with_conversation(a, first.clone())
        .with_peer(b, Peer::Accepts)
        .with_conversation(b, second.clone());
    let env = Env {
        clock: Box::new(clock.clone()),
        net: Box::new(net),
        arena: ArenaPolicy::new(16, 0).unwrap(),
        waker: None,
    };
    let mut m = Multi::new(env).unwrap();
    let tree = mime_tree(crate::mime::Content::Bytes(
        curl_alloc::TryArc::try_new(b"v".to_vec()).unwrap(),
    ));
    let ran = get(&mut m, "/a", first, |o| {
        o.method = Method::Post;
        o.upload = mime_source(tree);
        o.http.follow = Follow::All;
        o.http.unrestricted_auth = true;
        *o.login.make_mut().unwrap() = crate::options::Login::from_pair(b"u:p").unwrap();
        o.http.auth = crate::options::HttpAuth(AuthMethods::DIGEST);
    });
    assert_eq!(ran.result, Ok(()));
    assert_eq!(ran.seen.body(), b"ok\n");
    let typed = format!(
        "Content-Type: multipart/form-data; boundary=------------------------{}\r\n",
        "A".repeat(22)
    );
    let head_of = |text: &str, n: usize| text.split("POST ").nth(n).unwrap().to_owned();
    let text = String::from_utf8_lossy(&ran.request).into_owned();
    let probe = head_of(&text, 1);
    assert!(probe.ends_with("Content-Length: 0\r\n\r\n"), "{probe}");
    assert!(head_of(&text, 2).contains(&typed), "{text}");
    let text = String::from_utf8_lossy(&second.received()).into_owned();
    let probe = head_of(&text, 1);
    assert!(
        probe.ends_with(&format!("Content-Length: 0\r\n{typed}\r\n")),
        "{probe}"
    );
    assert!(head_of(&text, 2).contains(&typed), "{text}");
}

/// A tree of unknown size goes chunked, in C's pieces.
#[test]
fn a_mime_post_of_unknown_size_goes_chunked() {
    let stream = Stream::new(b"ab");
    let tree = mime_tree(crate::mime::Content::Read {
        handler: Handler::read(stream.clone()).unwrap(),
        rewind: None,
        size: None,
    });
    let ran = run("/p", OK_EMPTY, false, |o| {
        o.method = Method::Post;
        o.upload = mime_source(tree);
        o.http.headers = UserHeaders::new([&b"Expect:"[..]]).unwrap();
    });
    assert_eq!(ran.result, Ok(()));
    let text = String::from_utf8_lossy(&ran.request);
    assert!(
        text.contains("Transfer-Encoding: chunked\r\nContent-Type: multipart/form-data; boundary=")
    );
    assert!(text.contains("\r\n\r\nab\r\n"), "{text}");
    assert!(text.ends_with("--\r\n\r\n0\r\n\r\n"), "{text}");
}

/// A source with no tree posts an empty body, untyped (test 584).
#[test]
fn a_mime_post_without_a_tree_is_empty() {
    struct Gone;
    impl crate::mime::MimeSource for Gone {
        fn mime(
            &self,
        ) -> Result<Option<curl_alloc::TryArc<crate::mime::Mime>>, crate::mime::MimeError> {
            Ok(None)
        }
    }
    let ran = run("/p", OK_EMPTY, false, |o| {
        o.method = Method::Post;
        o.upload = UploadSource::Mime(Handler::mime(Gone).unwrap());
    });
    assert_eq!(ran.result, Ok(()));
    assert!(
        ran.request
            .ends_with(b"Accept: */*\r\nContent-Length: 0\r\n\r\n"),
        "{}",
        ran.request.escape_ascii()
    );
}

/// A one-part tree whose part `stream` reads, its size known, rewound by
/// the stream if `rewinds`.
fn streamed_tree(stream: &Stream, rewinds: bool) -> UploadSource {
    mime_source(mime_tree(crate::mime::Content::Read {
        handler: Handler::read(stream.clone()).unwrap(),
        rewind: rewinds.then(|| Handler::rewind(stream.clone()).unwrap()),
        size: Some(stream.data.len() as u64),
    }))
}

/// A tree read by its handlers is started over by them: for a redirect
/// that sends it again, once it was read (`cr_mime_cntrl`), and for the
/// next transfer that sends it, as a request reached its part
/// (`Curl_creader_set_mime`).
#[test]
fn a_tree_is_started_over_by_its_handlers() {
    // Each on a connection of its own: a body's blank line would read
    // to the fake peer as a request's head.
    let stream = Stream::new(b"abc");
    let first = Conversation::new(&redirect(307, "/b"), true);
    let second = Conversation::new(OK, true);
    let third = Conversation::new(OK, true);
    let mut m = serving(Peer::Accepts, &[&first, &second, &third]);
    let ran = get(&mut m, "/a", first.clone(), |o| {
        o.method = Method::Post;
        o.upload = streamed_tree(&stream, true);
        o.http.follow = Follow::All;
    });
    assert_eq!(ran.result, Ok(()));
    assert_eq!(stream.rewinds.get(), 1);
    let body = |c: &Conversation| {
        String::from_utf8_lossy(&c.received())
            .matches("\r\n\r\nabc\r\n--")
            .count()
    };
    assert_eq!((body(&first), body(&second)), (1, 1));
    assert!(
        ran.seen
            .text()
            .contains(&"Need to rewind upload for next request\n".to_string())
    );
    let ran = get_with(&mut m, ran.easy, "/c", third.clone(), |_| {});
    assert_eq!(ran.result, Ok(()));
    assert_eq!(stream.rewinds.get(), 2);
    assert_eq!(body(&third), 1);
}

/// A tree whose part was read and cannot be rewound cannot be sent
/// again: not to a redirect, nor by the next transfer; one whose rewind
/// fails neither.
#[test]
fn a_tree_that_cannot_start_over_is_not_sent_again() {
    for rewinds in [false, true] {
        let stream = Stream::new(b"abc");
        let mut source = streamed_tree(&stream, rewinds);
        if rewinds {
            struct Refuses;
            impl crate::handler::Rewind for Refuses {
                fn rewind(
                    &self,
                    _: &mut TransferCx<'_>,
                ) -> Result<(), crate::handler::RewindFailed> {
                    Err(crate::handler::RewindFailed)
                }
            }
            source = mime_source(mime_tree(crate::mime::Content::Read {
                handler: Handler::read(stream.clone()).unwrap(),
                rewind: Some(Handler::rewind(Refuses).unwrap()),
                size: Some(3),
            }));
        }
        let first = redirect(307, "/b");
        let (mut m, talk, _) = server(&[&first, OK], false);
        let ran = get(&mut m, "/a", talk.clone(), |o| {
            o.method = Method::Post;
            o.upload = source;
            o.http.follow = Follow::All;
        });
        assert_eq!(ran.result, Err(ErrorKind::SendFailRewind), "{rewinds}");
        assert!(
            ran.seen
                .text()
                .contains(&"Cannot rewind mime/post data\n".to_string()),
            "{:?}",
            ran.seen.text()
        );
        let ran = get_with(&mut m, ran.easy, "/c", talk, |o| o.http.follow = Follow::No);
        assert_eq!(ran.result, Err(ErrorKind::SendFailRewind), "{rewinds}");
    }
}

/// A probe sends none of the tree, so it reads none of it: nothing is
/// rewound before the request that sends it.
#[test]
fn a_probe_reads_none_of_the_tree() {
    let stream = Stream::new(b"abc");
    let (mut m, talk, _) = server(&[DIGEST_CHALLENGE, OK], false);
    let ran = get(&mut m, "/a", talk, |o| {
        o.method = Method::Post;
        o.upload = streamed_tree(&stream, true);
        *o.login.make_mut().unwrap() = crate::options::Login::from_pair(b"u:p").unwrap();
        o.http.auth = crate::options::HttpAuth(AuthMethods::DIGEST);
    });
    assert_eq!(ran.result, Ok(()));
    assert_eq!(stream.rewinds.get(), 0);
    let text = String::from_utf8_lossy(&ran.request).into_owned();
    assert_eq!(text.matches("\r\n\r\nabc\r\n--").count(), 1, "{text}");
    assert!(
        !ran.seen
            .text()
            .iter()
            .any(|l| l.starts_with("Need to rewind")),
        "{:?}",
        ran.seen.text()
    );
}

/// A part's handler pausing pauses the sending of the tree, until the
/// application lets it go on. Its pause after the part's head, in the
/// fill that gave the head, is the next read's: the handler is not
/// called again until then (`lastreadstatus`).
#[test]
fn a_tree_s_handler_pauses_its_sending() {
    struct PausesOnce(Stream, Arc<crate::test_cell::Cell<u32>>);
    impl crate::handler::ReadHandler for PausesOnce {
        fn read(&self, cx: &mut TransferCx<'_>, buf: &mut [u8]) -> crate::handler::Read {
            self.1.set(self.1.get() + 1);
            if self.1.get() == 1 {
                return crate::handler::Read::Pause;
            }
            self.0.read(cx, buf)
        }
    }
    let (mut m, talk, _) = server(&[OK_EMPTY], false);
    let mut e = Easy::new();
    let o = e.options_mut();
    o.set_url(Some(format!("http://127.0.0.1:{PORT}/p").as_bytes()))
        .unwrap();
    o.method = Method::Post;
    let calls = Arc::<crate::test_cell::Cell<u32>>::default();
    o.upload = mime_source(mime_tree(crate::mime::Content::Read {
        handler: Handler::read(PausesOnce(Stream::new(b"abc"), calls.clone())).unwrap(),
        rewind: None,
        size: Some(3),
    }));
    let id = m.add(Box::new(e), (), &mut NoEvents).unwrap();
    for _ in 0..10 {
        m.perform(&mut NoEvents).unwrap();
    }
    let sent = talk.received();
    assert!(sent.ends_with(b"\r\n\r\n"), "{}", sent.escape_ascii());
    assert_eq!(calls.get(), 1, "not called again while paused");
    m.pause(id, PauseRequest::CONT, &mut NoEvents).unwrap();
    let result = drive_to_completion(&mut m, id, &mut NoEvents).unwrap();
    assert_eq!(result, Ok(()));
    let sent = String::from_utf8_lossy(&talk.received()).into_owned();
    assert!(sent.contains("\r\n\r\nabc\r\n--"), "{sent}");
}

/// A handler is given no more room than is left of the body's size, so
/// it cannot send past it.
#[test]
fn a_handler_is_given_no_room_past_the_size() {
    struct OneThenAll(Arc<crate::test_cell::Cell<usize>>);
    impl crate::handler::ReadHandler for OneThenAll {
        fn read(&self, _: &mut TransferCx<'_>, buf: &mut [u8]) -> crate::handler::Read {
            let data = b"abcdefghij";
            let at = self.0.get();
            let n = if at == 0 {
                1
            } else {
                buf.len().min(data.len() - at)
            };
            buf[..n].copy_from_slice(&data[at..at + n]);
            self.0.set(at + n);
            std::num::NonZeroUsize::new(n)
                .map_or(crate::handler::Read::Eof, crate::handler::Read::Data)
        }
    }
    let ran = run("/p", OK_EMPTY, false, |o| {
        o.method = Method::Post;
        o.upload = UploadSource::Read {
            handler: Handler::read(OneThenAll(Arc::default())).unwrap(),
            rewind: None,
            size: Some(5),
        };
    });
    assert_eq!(ran.result, Ok(()));
    assert!(
        ran.request.ends_with(b"\r\n\r\nabcde"),
        "{}",
        ran.request.escape_ascii()
    );
}

/// Under a send limit, a body held for a 100 earns its tokens from when
/// the head went, as C's readers are asked for it then: after a wait of
/// three seconds, the burst of 32 KiB goes at once, a second's worth in
/// each send and each pass (`xfer_send`).
#[test]
fn a_body_held_for_a_100_earns_from_the_head() {
    const RATE: u64 = 10_000;
    let (mut m, talk, clock) = server(&[], false);
    let seen = Seen::default();
    let mut e = Easy::new();
    let o = e.options_mut();
    o.set_url(Some(format!("http://127.0.0.1:{PORT}/").as_bytes()))
        .unwrap();
    o.method = Method::Post;
    o.upload = UploadSource::Bytes(curl_alloc::TryArc::try_new(vec![b'x'; 200_000]).unwrap());
    o.http.headers = UserHeaders::new([&b"Expect: 100-continue"[..]]).unwrap();
    o.http.continue_wait = crate::options::ContinueWait(Duration::from_secs(3));
    o.flow.make_mut().unwrap().max_send_speed = NonZeroU64::new(RATE);
    o.output.verbose = true;
    o.callbacks.debug = Some(Handler::debug(seen.clone()).unwrap());
    m.add(Box::new(e), (), &mut NoEvents).unwrap();
    m.perform(&mut NoEvents).unwrap();
    // The connect started in the first pass is taken in the next.
    m.perform(&mut NoEvents).unwrap();
    assert_eq!(after_head(&talk.received()), 0, "held for the 100");
    clock.advance(Duration::from_secs(3));
    m.perform(&mut NoEvents).unwrap();
    assert_eq!(after_head(&talk.received()) as u64, RATE, "a send a pass");
    for _ in 0..20 {
        m.perform(&mut NoEvents).unwrap();
    }
    let sends: Vec<usize> = seen.of("dataout").iter().map(Vec::len).collect();
    assert_eq!(sends, [10_000, 10_000, 10_000, 2768]);
}

/// The head does not count against a send's second's worth of the body:
/// a pass sends the head beside as much of the body as the limit lets
/// go, from as many fills as that takes.
#[test]
fn a_head_goes_beside_a_second_s_worth_of_the_body() {
    // Under the least burst, a second's worth alone: the limit starts
    // afresh as the body is first read (`Curl_rlimit_start`).
    for (rate, sends_want) in [
        (10_000, &[10_000][..]),
        (50_000, &[50_000]),
        (65_409, &[65_409]),
        (65_500, &[65_409, 91]),
    ] {
        let (mut m, talk, _clock) = server(&[], false);
        let seen = Seen::default();
        let mut e = Easy::new();
        let o = e.options_mut();
        o.set_url(Some(format!("http://127.0.0.1:{PORT}/").as_bytes()))
            .unwrap();
        o.method = Method::Post;
        o.upload = UploadSource::Bytes(curl_alloc::TryArc::try_new(vec![b'x'; 200_000]).unwrap());
        o.flow.make_mut().unwrap().max_send_speed = NonZeroU64::new(rate);
        o.output.verbose = true;
        o.callbacks.debug = Some(Handler::debug(seen.clone()).unwrap());
        m.add(Box::new(e), (), &mut NoEvents).unwrap();
        m.perform(&mut NoEvents).unwrap();
        // The connect started in the first pass is taken in the next.
        m.perform(&mut NoEvents).unwrap();
        let head: Vec<usize> = seen.of("out").iter().map(Vec::len).collect();
        let sends: Vec<usize> = seen.of("dataout").iter().map(Vec::len).collect();
        assert_eq!((&head[..], &sends[..]), (&[127][..], sends_want), "{rate}");
        assert_eq!(
            talk.received().len() as u64,
            127 + rate.min(65_500),
            "{rate}"
        );
    }
}

/// A 417 to a request that announced nothing is an error like any: the
/// body stops, and the request is not made again.
#[test]
fn a_417_without_expect_stops_the_body() {
    let refused = b"HTTP/1.1 417 Expectation Failed\r\nContent-Length: 0\r\n\r\n";
    let (mut m, talk, _) = server(&[refused], false);
    let ran = get(&mut m, "/a", talk.clone(), |o| {
        o.method = Method::Post;
        o.upload = UploadSource::Bytes(curl_alloc::TryArc::try_new(vec![b'x'; 300_000]).unwrap());
    });
    assert_eq!(ran.result, Ok(()));
    let text = ran.seen.text();
    assert!(
        text.iter()
            .any(|l| l == "HTTP error before end of send, stop sending\n"),
        "{text:?}"
    );
    assert!(!text.iter().any(|l| l.contains("417 while")), "{text:?}");
    assert_eq!(
        talk.received().windows(5).filter(|w| w == b"POST ").count(),
        1
    );
}

/// A tree of known size whose handler ends short of it fails the read,
/// saying how much came (`cr_mime_read`).
#[test]
fn a_tree_ending_short_of_its_size_fails() {
    let ran = run("/p", OK_EMPTY, false, |o| {
        o.method = Method::Post;
        o.upload = mime_source(mime_tree(crate::mime::Content::Read {
            handler: Handler::read(Stream::new(b"ab")).unwrap(),
            rewind: None,
            size: Some(5),
        }));
    });
    assert_eq!(ran.result, Err(ErrorKind::ReadError));
    let text = ran.seen.text();
    assert!(
        text.iter()
            .any(|l| l.starts_with("client mime read EOF fail, only ")
                && l.ends_with(" of needed bytes read\n")),
        "{text:?}"
    );
}

/// A link-local address given without its scope is reached on the
/// interface that has one (cf-socket.c's `get_scope_id`).
#[test]
fn a_link_local_address_takes_the_interface_s_scope() {
    let clock = ManualClock::new().unwrap();
    let ip: std::net::Ipv6Addr = "fe80::1".parse().unwrap();
    let at = SocketAddr::V6(std::net::SocketAddrV6::new(ip, PORT, 0, 3));
    let talk = Conversation::replies(&[OK], false);
    let net = FakeNet::new(clock.clone())
        .with_link_local_scope(std::num::NonZeroU32::new(3).unwrap())
        .with_peer(at, Peer::Accepts)
        .with_conversation(at, talk.clone());
    let env = Env {
        clock: Box::new(clock),
        net: Box::new(net),
        arena: ArenaPolicy::new(16, 0).unwrap(),
        waker: None,
    };
    let mut m: Multi = Multi::new(env).unwrap();
    let mut e = Easy::new();
    e.options_mut()
        .set_url(Some(format!("http://[fe80::1]:{PORT}/").as_bytes()))
        .unwrap();
    let id = m.add(Box::new(e), (), &mut NoEvents).unwrap();
    assert_eq!(
        drive_to_completion(&mut m, id, &mut NoEvents).unwrap(),
        Ok(())
    );
    assert!(talk.received().starts_with(b"GET / HTTP/1.1\r\n"));
}

/// Set in the child process `the_system_s_ipv6_probe_is_the_system_s`
/// runs itself in.
const PROBE_CHILD: &str = "CURL_CORE_PROBE_CHILD";

/// The system's network asks the system whether IPv6 works: yes here,
/// and no once no descriptor is left to open a socket with (run in a
/// child process, as it uses them all up). A fake network says yes
/// unless it is made without IPv6.
#[test]
#[cfg_attr(miri, ignore = "Miri cannot start a process")]
fn the_system_s_ipv6_probe_is_the_system_s() {
    use crate::conn::io::Net as _;
    if std::env::var_os(PROBE_CHILD).is_some() {
        let mut held = Vec::new();
        let err = loop {
            match std::fs::File::open("/dev/null") {
                Ok(f) => held.push(f),
                Err(e) => break e,
            }
        };
        assert_eq!(err.raw_os_error(), Some(24), "EMFILE: {err}");
        assert_eq!(crate::conn::io::SystemNet.probe_ipv6(), Ok(false));
        return;
    }
    assert_eq!(
        crate::conn::io::SystemNet.probe_ipv6(),
        curl_os::net::probe_ipv6().map_err(|_| curl_alloc::OutOfMemory)
    );
    assert_eq!(crate::conn::io::SystemNet.probe_ipv6(), Ok(true));
    let clock = ManualClock::new().unwrap();
    assert_eq!(FakeNet::new(clock.clone()).probe_ipv6(), Ok(true));
    assert_eq!(FakeNet::new(clock).without_ipv6().probe_ipv6(), Ok(false));
    // Few descriptors, so they run out at once.
    let name = "proto::http::tests::the_system_s_ipv6_probe_is_the_system_s";
    let out = std::process::Command::new("sh")
        .args(["-c", "ulimit -n 64 && exec \"$0\" \"$@\""])
        .arg(std::env::current_exe().unwrap())
        .args([name, "--exact", "--test-threads=1"])
        .env(PROBE_CHILD, "1")
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "{stdout}{stderr}");
    assert!(stdout.contains("1 passed"), "the child ran it: {stdout}");
}

/// The system's network asks the system for the scope.
#[test]
fn the_system_s_scope_is_the_system_s() {
    use crate::conn::io::Net as _;
    assert_eq!(
        crate::conn::io::SystemNet.link_local_scope(),
        curl_os::net::link_local_scope()
    );
}

/// The 100 that pauses the sending as it comes does not start it: the
/// body's handler is not called until the application lets it go on.
#[test]
fn a_100_that_pauses_waits_for_the_application() {
    struct PausesOn100;
    impl HeaderHandler for PausesOn100 {
        fn header(&self, cx: &mut TransferCx<'_>, line: &[u8], _: HeaderOrigin) -> Write {
            if line.starts_with(b"HTTP/1.1 100") {
                let me = cx.me();
                cx.pause(me, PauseRequest::SEND).unwrap();
            }
            Write::Accepted
        }
    }
    let continued = [&b"HTTP/1.1 100 Continue\r\n\r\n"[..], OK_EMPTY].concat();
    let (mut m, talk, _) = server(&[&continued], false);
    let mut e = Easy::new();
    let o = e.options_mut();
    o.set_url(Some(format!("http://127.0.0.1:{PORT}/").as_bytes()))
        .unwrap();
    o.method = Method::Post;
    let stream = Stream::new(b"abc");
    let at = stream.at.clone();
    o.upload = UploadSource::Read {
        handler: Handler::read(stream).unwrap(),
        rewind: None,
        size: Some(3),
    };
    o.http.headers = UserHeaders::new([&b"Expect: 100-continue"[..]]).unwrap();
    o.callbacks.header = Some(Handler::header(PausesOn100).unwrap());
    let id = m.add(Box::new(e), (), &mut NoEvents).unwrap();
    for _ in 0..10 {
        m.perform(&mut NoEvents).unwrap();
    }
    let sent = talk.received();
    assert!(sent.ends_with(b"\r\n\r\n"), "{}", sent.escape_ascii());
    assert_eq!(at.get(), 0, "the handler is not called while paused");
    m.pause(id, PauseRequest::CONT, &mut NoEvents).unwrap();
    let result = drive_to_completion(&mut m, id, &mut NoEvents).unwrap();
    assert_eq!(result, Ok(()));
    assert!(talk.received().ends_with(b"\r\n\r\nabc"));
}

/// A body held for a 100 whose sending is paused as the head goes is
/// not asked for, so its wait starts only once the application lets it
/// go on, not while it is paused (`cr_exp100_read` is not called under
/// `KEEP_SEND_PAUSE`).
#[test]
fn the_wait_for_a_100_starts_once_a_pause_ends() {
    struct PausesOnHead;
    impl DebugHandler for PausesOnHead {
        fn debug(&self, cx: &mut TransferCx<'_>, kind: DebugKind, _: &[u8]) {
            if matches!(kind, DebugKind::HeaderOut) {
                let me = cx.me();
                cx.pause(me, PauseRequest::SEND).unwrap();
            }
        }
    }
    // A peer that never answers.
    let (mut m, talk, clock) = server(&[], false);
    let mut e = Easy::new();
    let o = e.options_mut();
    o.set_url(Some(format!("http://127.0.0.1:{PORT}/").as_bytes()))
        .unwrap();
    o.method = Method::Post;
    o.upload = UploadSource::Bytes(curl_alloc::TryArc::try_new(b"abc".to_vec()).unwrap());
    o.http.headers = UserHeaders::new([&b"Expect: 100-continue"[..]]).unwrap();
    o.output.verbose = true;
    o.callbacks.debug = Some(Handler::debug(PausesOnHead).unwrap());
    let id = m.add(Box::new(e), (), &mut NoEvents).unwrap();
    for _ in 0..4 {
        m.perform(&mut NoEvents).unwrap();
    }
    assert!(talk.received().ends_with(b"\r\n\r\n"), "the head went");
    // Paused for longer than the wait.
    clock.advance(Duration::from_secs(5));
    m.perform(&mut NoEvents).unwrap();
    m.pause(id, PauseRequest::CONT, &mut NoEvents).unwrap();
    m.perform(&mut NoEvents).unwrap();
    assert_eq!(after_head(&talk.received()), 0, "the wait starts now");
    clock.advance(Duration::from_millis(999));
    m.perform(&mut NoEvents).unwrap();
    assert_eq!(after_head(&talk.received()), 0, "and is a second long");
    clock.advance(Duration::from_millis(1));
    m.perform(&mut NoEvents).unwrap();
    assert_eq!(after_head(&talk.received()), 3, "then the body goes");
}

/// The answer to `CONNECT` is read a byte at a time, the transfer taken
/// stock of after each (`recv_CONNECT_resp`): a header line more in the
/// answer is as many more calls of the progress handler as it has bytes.
#[test]
fn a_tunnel_s_answer_takes_stock_after_each_byte() {
    let calls = |answer: &[u8]| {
        let (mut m, talk, _) = server(&[answer, OK], false);
        let progress = AbortsAt::default();
        let ran = get(&mut m, "/", talk, |o| {
            tunneled(o);
            o.progress =
                crate::options::Progress::Handler(Handler::progress(progress.clone()).unwrap());
        });
        assert_eq!(ran.result, Ok(()));
        progress.calls.get()
    };
    let plain = calls(TUNNEL_UP);
    let more = calls(b"HTTP/1.1 200 Fine\r\nX: abc\r\nY: z\r\n\r\n");
    assert_eq!(more - plain, 14);
}

/// A signature asked of a proxy is as a method not implemented, and the
/// rest of what was asked still picks among what the proxy offers: Basic
/// over the Digest it was not asked for (`output_auth_headers`,
/// `pickoneauth`).
#[test]
fn a_proxy_asked_for_a_signature_picks_from_the_rest() {
    let challenge = b"HTTP/1.1 407 Who\r\n\
        Proxy-Authenticate: Digest realm=\"p\", nonce=\"1\"\r\n\
        Proxy-Authenticate: Basic realm=\"p\"\r\nContent-Length: 0\r\n\r\n";
    let (mut m, talk, _) = server(&[challenge, OK], false);
    let ran = get(&mut m, "/", talk, |o| {
        o.set_url(Some(b"http://origin.example/a")).unwrap();
        o.proxy.make_mut().unwrap().url = Some(format!("127.0.0.1:{PORT}").into_bytes());
        o.proxy.make_mut().unwrap().user = Some(b"u".to_vec());
        o.proxy.make_mut().unwrap().password = Some(b"p".to_vec());
        o.proxy.make_mut().unwrap().auth =
            crate::options::HttpAuth(AuthMethods::BASIC | AuthMethods::AWS_SIGV4);
    });
    assert_eq!(ran.result, Ok(()));
    let text = String::from_utf8_lossy(&ran.request).into_owned();
    assert!(
        text.contains("\r\nProxy-Authorization: Basic dTpw\r\n"),
        "{text}"
    );
    assert_eq!(ran.easy.report().proxy_auth_used(), AuthMethods::BASIC);
}

/// A tree not read yet, its request answered while it waits for a 100,
/// needs no rewind to be sent to where the answer redirects
/// (`cr_mime_needs_rewind`).
#[test]
fn a_tree_not_read_needs_no_rewind() {
    let stream = Stream::new(b"abc");
    let first = Conversation::new(&redirect(307, "/b"), true);
    let continued = [&b"HTTP/1.1 100 Continue\r\n\r\n"[..], OK].concat();
    let second = Conversation::new(&continued, true);
    let mut m = serving(Peer::Accepts, &[&first, &second]);
    let ran = get(&mut m, "/a", first.clone(), |o| {
        o.method = Method::Post;
        o.upload = streamed_tree(&stream, true);
        o.http.headers = UserHeaders::new([&b"Expect: 100-continue"[..]]).unwrap();
        o.http.follow = Follow::All;
    });
    assert_eq!(ran.result, Ok(()));
    let said = ran.seen.text();
    assert!(
        !said.contains(&"Need to rewind upload for next request\n".to_string()),
        "{said:?}"
    );
    assert_eq!(stream.rewinds.get(), 0);
    let sent = String::from_utf8_lossy(&second.received()).into_owned();
    assert!(sent.contains("\r\n\r\nabc\r\n--"), "{sent}");
}

/// A Digest probe after a request that sent the tree types itself with
/// the head lines that request sent, as C sends the tree's headers it
/// made last (`http_add_content_hds`; the C library, one easy handle
/// posting one tree without and then with Digest, sends
/// `Content-Length: 0` and the earlier `Content-Type` in its probe).
#[test]
fn a_probe_after_a_sent_tree_sends_its_type() {
    let tree = mime_tree(crate::mime::Content::Bytes(
        curl_alloc::TryArc::try_new(b"b".to_vec()).unwrap(),
    ));
    let first = Conversation::new(OK, true);
    let second = Conversation::replies(&[DIGEST_CHALLENGE, OK], false);
    let mut m = serving(Peer::Accepts, &[&first, &second]);
    let ran = get(&mut m, "/1", first.clone(), |o| {
        o.method = Method::Post;
        o.upload = mime_source(tree);
    });
    assert_eq!(ran.result, Ok(()));
    let sent = String::from_utf8_lossy(&first.received()).into_owned();
    let typed = sent
        .lines()
        .find(|l| l.starts_with("Content-Type: multipart/form-data; boundary="))
        .unwrap()
        .to_string();
    let ran = get_with(&mut m, ran.easy, "/2", second.clone(), |o| {
        *o.login.make_mut().unwrap() = crate::options::Login::from_pair(b"u:p").unwrap();
        o.http.auth = crate::options::HttpAuth(AuthMethods::DIGEST);
    });
    assert_eq!(ran.result, Ok(()));
    let sent = String::from_utf8_lossy(&second.received()).into_owned();
    let probe = &sent[..sent.find("\r\n\r\n").unwrap() + 4];
    assert!(
        probe.ends_with(&format!("Content-Length: 0\r\n{typed}\r\n\r\n")),
        "{probe}"
    );
}

/// What the debug handler is given of each header line received, ids on
/// or off, for a line of `len` bytes.
fn header_traced(ids: bool, len: usize) -> Vec<u8> {
    let field = format!("A: {}\r\n", "x".repeat(len - 5));
    let reply = format!("HTTP/1.1 200 OK\r\n{field}Content-Length: 0\r\n\r\n");
    let (mut m, talk, _) = server(&[reply.as_bytes()], false);
    let mut e = Easy::new();
    if ids {
        let c = crate::components::Components::new().unwrap();
        c.configure(b"lib-ids");
        e.set_components(Some(c));
    }
    let ran = get_with(&mut m, e, "/", talk, |_| {});
    assert_eq!(ran.result, Ok(()));
    ran.seen.of("in").into_iter().nth(1).unwrap()
}

/// With the ids on, a line traced to the debug handler starts with them
/// when it is shorter than a trace line, cut and marked `...` where it
/// leaves no room for C's zero byte; a longer one goes as it is, and
/// without the ids every line does (`Curl_debug`, `trc_end_buf`).
#[test]
fn traced_bytes_take_the_ids_as_c_does() {
    // C's `TRC_LINE_MAX`.
    const LINE_MAX: usize = 2048;
    let ids = b"[0-0] ";
    let line = |len: usize| {
        let mut l = b"A: ".to_vec();
        l.extend(vec![b'x'; len - 5]);
        l.extend(b"\r\n");
        l
    };
    // Room left: whole, after the ids.
    let short = header_traced(true, 10);
    assert_eq!(short, [&ids[..], &line(10)].concat());
    // The ids and the line fill the trace line but for its zero byte.
    for len in [LINE_MAX - 1 - ids.len(), LINE_MAX - 1] {
        let cut = header_traced(true, len);
        assert_eq!(cut.len(), LINE_MAX - 1, "{len}");
        assert!(cut.starts_with(b"[0-0] A: xx"), "{len}");
        assert!(cut.ends_with(b"x...\n"), "{len}");
    }
    // As long as a trace line: as it is, no ids.
    assert_eq!(header_traced(true, LINE_MAX), line(LINE_MAX));
    // No ids: as it is.
    assert_eq!(header_traced(false, LINE_MAX - 1), line(LINE_MAX - 1));
    assert_eq!(header_traced(false, 10), line(10));
}
