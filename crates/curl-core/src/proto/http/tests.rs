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

/// What is not sent yet is refused before anything goes: a body to wait
/// for 100-continue for, or of unknown size; a resumed upload is not
/// HTTP's.
#[test]
fn bodies_not_sent_yet_are_refused() {
    let big = vec![b'x'; 1024 * 1024 + 1];
    assert_eq!(
        with_body(Method::Post, &big, |_| {}).result,
        Err(ErrorKind::NotBuiltIn)
    );
    let asked = with_body(Method::Post, b"a", |o| {
        o.http.headers = UserHeaders::new([&b"Expect: 100-continue"[..]]).unwrap();
    });
    assert_eq!(asked.result, Err(ErrorKind::NotBuiltIn));
    let chunked = with_body(Method::Upload, b"a", |o| {
        o.http.headers = UserHeaders::new([&b"Transfer-Encoding: chunked"[..]]).unwrap();
    });
    assert_eq!(chunked.result, Err(ErrorKind::NotBuiltIn));
    let not_asked = with_body(Method::Post, &big, |o| {
        o.http.headers = UserHeaders::new([&b"Expect:"[..]]).unwrap();
    });
    assert_eq!(not_asked.result, Ok(()), "the application asked for none");
    assert_eq!(not_asked.easy.report().sizes().upload(), big.len() as u64);
    let resumed = with_body(Method::Upload, b"a", |o| {
        o.resume = Some(Resume::At(NonZeroU64::new(1).unwrap()));
    });
    assert_eq!(resumed.result, Err(ErrorKind::BadFunctionArgument));
    assert!(resumed.request.is_empty());
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
