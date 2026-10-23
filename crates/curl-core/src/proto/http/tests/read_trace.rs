//! The read component's trace (`CURL_TRC_READ`): the readers a request's
//! body is read through, as C's client reader chain traces them, and
//! their reset as a request starts and ends. Each expected sequence is
//! the C build's for the same transfer.

use super::*;
use crate::components::Components;
use crate::options::UploadSource;

/// A handle tracing the read component.
fn tracing_read() -> Easy {
    let mut e = Easy::new();
    let c = Components::new().unwrap();
    c.configure(b"read");
    e.set_components(Some(c));
    e
}

/// The read component's lines a run traced, and the lines of the rewind
/// said around them.
fn read_lines(ran: &Ran) -> Vec<String> {
    ran.seen
        .text()
        .into_iter()
        .filter(|l| {
            l.starts_with("[READ] ")
                || l.starts_with("Need to rewind")
                || l.starts_with("Issue another")
        })
        .map(|l| l.trim_end().to_owned())
        .collect()
}

/// The room a request's buffer has behind a head of `head` bytes.
fn room_after(head: usize) -> usize {
    65536 - head
}

/// A POST of bytes the handle holds is read once, whole, through C's
/// buffer reader, behind the head in the request's buffer.
#[test]
fn bytes_are_read_through_the_buffer_reader() {
    let (mut m, talk, _) = server(&[OK], false);
    let ran = get_with(&mut m, tracing_read(), "/p", talk, |o| {
        o.method = Method::Post;
        o.upload = UploadSource::Bytes(curl_alloc::TryArc::try_new(b"a=b".to_vec()).unwrap());
    });
    assert_eq!(ran.result, Ok(()));
    let room = room_after(ran.request.len() - 3);
    assert_eq!(
        read_lines(&ran),
        [
            "[READ] client_reset, clear readers".to_owned(),
            "[READ] add buf reader, len=3 -> 0".to_owned(),
            format!("[READ] cr_buf_read(len={room}) -> 0, nread=3, eos=1"),
            format!("[READ] client_read(len={room}) -> 0, nread=3, eos=1"),
            "[READ] client_reset, clear readers".to_owned(),
        ]
    );
}

/// A body of unknown size from the application's handler goes chunked,
/// after a 100: each piece read is a chunk, then the last, empty one, the
/// chunk stage leaving room for the most framing a chunk takes. The C
/// build traces the same for `-T -`.
#[test]
fn a_handler_s_pieces_are_read_into_chunks() {
    let continued = [&b"HTTP/1.1 100 Continue\r\n\r\n"[..], OK].concat();
    // The 100 comes after the first read looks for it, as from the test
    // suite's server.
    let (mut m, talk, _) = server(&[&continued], false);
    let talk = talk.late_replies();
    let ran = get_with(&mut m, tracing_read(), "/p", talk, |o| {
        o.method = Method::Upload;
        o.upload = pieces(&[b"abc"]);
    });
    assert_eq!(ran.result, Ok(()));
    let head = ran.request.len() - b"3\r\nabc\r\n0\r\n\r\n".len();
    let room = room_after(head);
    assert_eq!(
        read_lines(&ran),
        [
            "[READ] client_reset, clear readers".to_owned(),
            "[READ] add fread reader, len=-1 -> 0".to_owned(),
            format!("[READ] client_read(len={room}) -> 0, nread=0, eos=0"),
            "[READ] client_read(len=65536) -> 0, nread=0, eos=0".to_owned(),
            "[READ] cr_in_read(len=65524, total=-1, read=3) -> 0, nread=3, eos=0".to_owned(),
            "[READ] http_chunk, made chunk of 3 bytes -> 0".to_owned(),
            "[READ] client_read(len=65536) -> 0, nread=8, eos=0".to_owned(),
            "[READ] cr_in_read(len=65524, total=-1, read=3) -> 0, nread=0, eos=1".to_owned(),
            "[READ] http_chunk, added last, empty chunk".to_owned(),
            "[READ] client_read(len=65536) -> 0, nread=5, eos=1".to_owned(),
            "[READ] client_reset, clear readers".to_owned(),
        ]
    );
}

/// A body redirected with a 307 is to be sent again: said as the head
/// asks for it, kept as the request ends, and rewound before the next is
/// issued.
#[test]
fn a_body_sent_again_is_kept_and_rewound() {
    let first = redirect(307, "/b");
    let (mut m, talk, _) = server(&[&first, OK], false);
    let ran = get_with(&mut m, tracing_read(), "/a", talk, |o| {
        o.method = Method::Post;
        o.upload = UploadSource::Bytes(curl_alloc::TryArc::try_new(b"a=b".to_vec()).unwrap());
        o.http.follow = Follow::All;
    });
    assert_eq!(ran.result, Ok(()));
    let lines = read_lines(&ran);
    let at = lines
        .iter()
        .position(|l| l == "[READ] client reader needs rewind before next request")
        .unwrap();
    assert_eq!(
        lines[at..at + 5],
        [
            "[READ] client reader needs rewind before next request",
            "Need to rewind upload for next request",
            "[READ] client_reset, will rewind reader",
            "[READ] client start, rewind readers",
            "Issue another request to this URL: 'http://127.0.0.1:8990/b'",
        ]
    );
    assert_eq!(lines[at + 5], "[READ] client_reset, clear readers");
}

/// A body held for a 100 is asked for and gives nothing, behind the head
/// and as the wait starts; then it is read.
#[test]
fn a_body_held_for_a_100_gives_nothing_until_it_comes() {
    let continued = [&b"HTTP/1.1 100 Continue\r\n\r\n"[..], OK_EMPTY].concat();
    // The 100 comes after the first read looks for it.
    let (mut m, talk, _) = server(&[&continued], false);
    let talk = talk.late_replies();
    let ran = get_with(&mut m, tracing_read(), "/p", talk, |o| {
        o.method = Method::Post;
        o.upload = UploadSource::Bytes(curl_alloc::TryArc::try_new(b"a=b".to_vec()).unwrap());
        o.http.headers = UserHeaders::new([&b"Expect: 100-continue"[..]]).unwrap();
    });
    assert_eq!(ran.result, Ok(()));
    let room = room_after(ran.request.len() - 3);
    assert_eq!(
        read_lines(&ran)[1..6],
        [
            "[READ] add buf reader, len=3 -> 0".to_owned(),
            format!("[READ] client_read(len={room}) -> 0, nread=0, eos=0"),
            "[READ] client_read(len=65536) -> 0, nread=0, eos=0".to_owned(),
            "[READ] cr_buf_read(len=65536) -> 0, nread=3, eos=1".to_owned(),
            "[READ] client_read(len=65536) -> 0, nread=3, eos=1".to_owned(),
        ]
    );
}

/// A request retried on a fresh connection keeps its readers to rewind
/// them, whatever it sends (`Curl_retry_request`). The C build traces
/// the same lines for the same exchange.
#[test]
fn a_retried_request_keeps_its_readers_to_rewind() {
    let first = answers_once();
    let fresh = Conversation::new(OK, false);
    let mut m = serving(Peer::Accepts, &[&first, &fresh]);
    assert_eq!(get(&mut m, "/a", first.clone(), |_| {}).result, Ok(()));
    let ran = get_with(&mut m, tracing_read(), "/b", fresh, |_| {});
    assert_eq!(ran.result, Ok(()));
    let text: Vec<_> = ran
        .seen
        .text()
        .into_iter()
        .map(|l| l.trim_end().to_owned())
        .collect();
    let at = text
        .iter()
        .position(|l| l.starts_with("Connection died"))
        .unwrap();
    assert_eq!(
        text[at + 1..at + 5],
        [
            "[READ] client_reset, will rewind reader".to_owned(),
            "shutting down connection #0".to_owned(),
            "[READ] client start, rewind readers".to_owned(),
            format!("Issue another request to this URL: 'http://127.0.0.1:{PORT}/b'"),
        ]
    );
    assert_eq!(text[at + 5], "[READ] client_reset, clear readers");
}

/// A tree is read through C's mime reader: what the tree gave, then the
/// read it came to.
#[test]
fn a_tree_is_read_through_the_mime_reader() {
    let tree = mime_tree(crate::mime::Content::Bytes(
        curl_alloc::TryArc::try_new(b"v".to_vec()).unwrap(),
    ));
    let (mut m, talk, _) = server(&[OK], false);
    let ran = get_with(&mut m, tracing_read(), "/p", talk, |o| {
        o.method = Method::Post;
        o.upload = mime_source(tree);
    });
    assert_eq!(ran.result, Ok(()));
    let line = format!("--------------------------{}", "A".repeat(22));
    let size =
        format!("{line}\r\nContent-Disposition: form-data; name=\"f\"\r\n\r\nv\r\n{line}--\r\n")
            .len();
    let room = room_after(ran.request.len() - size);
    assert_eq!(
        read_lines(&ran)[1..4],
        [
            format!("[READ] cr_mime_read(len={size}), mime_read() -> {size}"),
            format!("[READ] cr_mime_read(len={size}, total={size}, read={size}) -> 0, {size}, 1"),
            format!("[READ] client_read(len={room}) -> 0, nread={size}, eos=1"),
        ]
    );
}

/// A chunked body whose application gives trailers says so as it adds
/// the last chunk, and what the handler came to.
#[test]
fn trailers_are_said_with_the_last_chunk() {
    struct Give(crate::handler::Trailers);
    impl crate::handler::TrailerHandler for Give {
        fn trailers(
            &self,
            _: &mut TransferCx<'_>,
            lines: &mut crate::handler::TrailerLines,
        ) -> crate::handler::Trailers {
            lines.add(b"X-A: 1").unwrap();
            self.0
        }
    }
    for (verdict, code) in [
        (crate::handler::Trailers::Done, 0),
        (crate::handler::Trailers::Abort, 42),
    ] {
        let (mut m, talk, _) = server(&[OK], false);
        let ran = get_with(&mut m, tracing_read(), "/p", talk, |o| {
            o.method = Method::Post;
            o.upload = pieces(&[b"abc"]);
            o.http.headers = UserHeaders::new([&b"Expect:"[..]]).unwrap();
            o.callbacks.trailer = Some(Handler::trailer(Give(verdict)).unwrap());
        });
        let lines = read_lines(&ran);
        let want =
            format!("[READ] http_chunk, added last chunk with trailers from client -> {code}");
        assert!(lines.contains(&want), "{lines:?}");
    }
}

/// A 417 heard once some of a body held for a 100 went has the body read
/// again for the request made without `Expect`: said before the rewind,
/// kept as the request ends and rewound before the next is issued
/// (`http_perhapsrewind`).
#[test]
fn a_417_while_sending_keeps_the_body_to_rewind() {
    let first = Conversation::replies(
        &[
            &b"HTTP/1.1 100 Continue\r\n\r\n"[..],
            b"HTTP/1.1 417 Nope\r\nContent-Length: 0\r\n\r\n",
        ],
        false,
    )
    .per_send();
    let second = Conversation::replies(&[OK_EMPTY], false);
    let mut m = serving(Peer::Accepts, &[&first, &second]);
    let stream = Stream::new(big_body(300_000));
    let ran = get_with(&mut m, tracing_read(), "/p", first, |o| {
        o.method = Method::Upload;
        o.upload = stream.source(true);
        o.http.headers = UserHeaders::new([&b"Expect: 100-continue"[..]]).unwrap();
    });
    assert_eq!(ran.result, Ok(()));
    let text: Vec<_> = ran
        .seen
        .text()
        .into_iter()
        .map(|l| l.trim_end().to_owned())
        .collect();
    let at = text
        .iter()
        .position(|l| l == "Got HTTP failure 417 while sending data")
        .expect("417 while sending");
    let lines: Vec<_> = text[at..]
        .iter()
        .filter(|l| {
            l.starts_with("[READ] client") || l.starts_with("Need to") || l.starts_with("Issue")
        })
        .cloned()
        .collect();
    assert_eq!(
        lines[..5],
        [
            "[READ] client reader needs rewind before next request".to_owned(),
            "Need to rewind upload for next request".to_owned(),
            "[READ] client_reset, will rewind reader".to_owned(),
            "[READ] client start, rewind readers".to_owned(),
            format!("Issue another request to this URL: 'http://127.0.0.1:{PORT}/p'"),
        ],
        "{text:?}"
    );
}

/// A body held for a 100 is asked for behind the head, and again as the
/// wait starts, in the pass after the one that sent the head's end
/// (`Curl_req_send_more` reads before it flushes), giving nothing each
/// time, as C's readers are asked (`cr_exp100_read`).
#[test]
fn a_body_held_for_a_100_is_asked_for_while_the_wait_runs() {
    let continued = [&b"HTTP/1.1 100 Continue\r\n\r\n"[..], OK_EMPTY].concat();
    let talk = Conversation::replies(&[&continued], false).late_replies();
    let mut m = serving(Peer::Accepts, &[&talk]);
    let e = tracing_read();
    e.components().unwrap().configure(b"read,tcp");
    let ran = get_with(&mut m, e, "/p", talk, |o| {
        o.method = Method::Post;
        o.upload = UploadSource::Bytes(curl_alloc::TryArc::try_new(b"a=b".to_vec()).unwrap());
        o.http.headers = UserHeaders::new([&b"Expect: 100-continue"[..]]).unwrap();
    });
    assert_eq!(ran.result, Ok(()));
    let held = "[READ] client_read(len=65536) -> 0, nread=0, eos=0";
    let lines = read_lines(&ran);
    assert_eq!(lines.iter().filter(|l| *l == held).count(), 1, "{lines:?}");
    // The wait started after the request's first read for its response.
    let text = ran.seen.text();
    let first_read = text
        .iter()
        .position(|l| l.starts_with("[TCP] recv("))
        .unwrap();
    let start = text.iter().position(|l| l.trim_end() == held).unwrap();
    assert!(first_read < start, "{text:?}");
}

/// Gives more than it has room for.
struct TooMuch;

impl crate::handler::ReadHandler for TooMuch {
    fn read(&self, _: &mut TransferCx<'_>, buf: &mut [u8]) -> crate::handler::Read {
        crate::handler::Read::Data(std::num::NonZeroUsize::new(buf.len() + 1).unwrap())
    }
}

/// The mime reader's lines a tree of one part read by `handler` traced,
/// `size` announced for it, and how the transfer ended.
fn mime_read(
    handler: Handler<dyn crate::handler::ReadHandler>,
    size: Option<u64>,
) -> (Result<(), ErrorKind>, Vec<String>) {
    let tree = mime_tree(crate::mime::Content::Read {
        handler,
        rewind: None,
        size,
    });
    let (mut m, talk, _) = server(&[OK], false);
    let ran = get_with(&mut m, tracing_read(), "/p", talk, |o| {
        o.method = Method::Post;
        o.upload = mime_source(tree);
    });
    let lines = read_lines(&ran)
        .into_iter()
        .filter(|l| l.starts_with("[READ] cr_mime_read"))
        .collect();
    (ran.result, lines)
}

/// A read that fails as C's `cr_mime_read` returns early says what the
/// tree gave and no more: a tree ending short of its size, and a handler
/// giving more than its room.
#[test]
fn a_mime_read_that_fails_early_says_only_what_it_got() {
    let (result, lines) = mime_read(Handler::read(Stream::new(b"abc")).unwrap(), Some(10));
    assert_eq!(result, Err(ErrorKind::ReadError));
    assert!(
        lines.last().unwrap().ends_with("mime_read() -> 0"),
        "{lines:?}"
    );
    let (result, lines) = mime_read(Handler::read(TooMuch).unwrap(), None);
    assert_eq!(result, Err(ErrorKind::ReadError));
    let last = lines.last().unwrap();
    assert!(
        last.contains("mime_read() -> ") && !last.contains("total="),
        "{lines:?}"
    );
}

/// Pauses the sending as the connect starts, and keeps the lines.
#[derive(Clone, Default)]
struct PausesOnTrying(Seen);

impl DebugHandler for PausesOnTrying {
    fn debug(&self, cx: &mut TransferCx<'_>, kind: DebugKind, data: &[u8]) {
        if kind == DebugKind::Text && data.starts_with(b"  Trying") {
            let me = cx.me();
            cx.pause(me, PauseRequest::SEND).unwrap();
        }
        self.0.debug(cx, kind, data);
    }
}

/// A body whose sending the application paused before the request is
/// not asked for while it stays paused, though the request waits for a
/// 100 (`Curl_req_send`'s check of the send pause).
#[test]
fn a_body_paused_from_the_start_is_not_asked_for() {
    let (mut m, talk, _) = server(&[OK_EMPTY], false);
    let mut e = tracing_read();
    let seen = PausesOnTrying::default();
    let o = e.options_mut();
    o.set_url(Some(format!("http://127.0.0.1:{PORT}/").as_bytes()))
        .unwrap();
    o.output.verbose = true;
    o.callbacks.debug = Some(Handler::debug(seen.clone()).unwrap());
    o.method = Method::Post;
    o.upload = UploadSource::Bytes(curl_alloc::TryArc::try_new(b"a=b".to_vec()).unwrap());
    o.http.headers = UserHeaders::new([&b"Expect: 100-continue"[..]]).unwrap();
    m.add(Box::new(e), (), &mut NoEvents).unwrap();
    for _ in 0..5 {
        m.perform(&mut NoEvents).unwrap();
    }
    assert!(
        talk.received().starts_with(b"POST / HTTP/1.1\r\n"),
        "the request went"
    );
    let lines: Vec<_> = seen
        .0
        .text()
        .into_iter()
        .filter(|l| l.starts_with("[READ] client_read"))
        .collect();
    assert_eq!(lines, Vec::<String>::new());
}
