//! The HTTP/2 filter's lines (`CURL_TRC_CF` of `cf-h2`, `[HTTP/2]`),
//! through the fake library. Each expected sequence is the C build's
//! against a local server with `--trace-config http/2` (pytest
//! `test_02_01` and `test_07_01` for h2, `CURL_DEBUG=all`), but for what
//! the fake does apart: its frames' lengths, a server that answers at
//! once, the settings it says, and prior knowledge, which adds the
//! filter's own two lines before the session's (`Curl_http2_switch`).

use super::*;
use crate::components::{Component, Components, Level};
use crate::http2::fake::FakeH2;
use crate::libraries::{Libraries, SharedLibraries};
use crate::options::HttpVersion;

/// Libraries with the fake HTTP/2 library.
fn with_h2() -> SharedLibraries {
    static FAKE: FakeH2 = FakeH2;
    SharedLibraries::new(Libraries {
        h2: Some(&FAKE),
        ..Libraries::NONE
    })
    .unwrap()
}

/// A handle with the fake HTTP/2 library, tracing the HTTP/2 filter.
fn tracing() -> Easy {
    let mut e = Easy::new();
    e.set_libraries(with_h2());
    let c = Components::new().unwrap();
    c.configure(b"http/2");
    e.set_components(Some(c));
    e
}

/// A verbose request by prior knowledge, its server answering each send
/// with the next of `replies`, its handle set by `set`.
fn h2_run(replies: &[&[u8]], set: impl FnOnce(&mut Options)) -> (Ran, Conversation) {
    let talk = Conversation::replies(replies, false).per_send();
    let mut m = serving(Peer::Accepts, &[&talk]);
    let ran = get_with(&mut m, tracing(), "/x", talk.clone(), |o| {
        o.http.version = HttpVersion::Http2Prior;
        set(o);
    });
    (ran, talk)
}

/// The filter's lines a run traced, past their ids, the stream's
/// fields (`infof`, not the filter's) left out.
fn h2_lines(seen: &Seen) -> Vec<String> {
    seen.text()
        .into_iter()
        .map(|l| l.trim_end().to_owned())
        .filter(|l| {
            l.strip_prefix("[HTTP/2] ")
                .is_some_and(|rest| !rest.contains("] [") && !rest.contains("OPENED"))
        })
        .collect()
}

fn expect(lines: &str) -> Vec<String> {
    lines
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .map(str::to_owned)
        .collect()
}

/// A GET: the session made and its SETTINGS framed as the filter
/// connects, to go with the request; the request submitted and sent;
/// then one read of the connection, a frame at a time, each frame told
/// whole after the fields it carried and before what it means, the
/// stream's DATA with its window, its close, the read's end, what the
/// read left to send, and the read's own line, all in C's order.
#[test]
fn a_get_traces_the_filter_s_lines_in_c_s_order() {
    let reply: &[u8] = b"S 100\nH 1 0\n:status: 200\ncontent-length: 5\n\nD 1 5 1\nhello";
    let (ran, _) = h2_run(&[reply], |_| {});
    assert_eq!(ran.result, Ok(()), "{:?}", ran.seen.text());
    assert_eq!(
        h2_lines(&ran.seen),
        expect(
            "[HTTP/2] added
             [HTTP/2] switching connection to HTTP/2
             [HTTP/2] [0] created h2 session
             [HTTP/2] [0] -> FRAME[SETTINGS, len=18]
             [HTTP/2] cf_connect() -> 0, 1,
             [HTTP/2] [1] submit -> 0, 75
             [HTTP/2] [1] -> FRAME[HEADERS, len=99, hend=1, eos=1]
             [HTTP/2] [1] cf_send(len=75) -> 0, 75, eos=1, h2 windows 2147483647-2147483647 \
                 (stream-conn), buffers 0-0 (stream-conn)
             [HTTP/2] [1] local window update by 10420224
             [HTTP/2] [0] ingress: read 57 bytes
             [HTTP/2] [0] <- FRAME[SETTINGS, len=6]
             [HTTP/2] [0] MAX_CONCURRENT_STREAMS: 100
             [HTTP/2] [0] ENABLE_PUSH: TRUE
             [HTTP/2] [1] status: HTTP/2 200
             [HTTP/2] [1] header: content-length: 5
             [HTTP/2] [1] <- FRAME[HEADERS, len=32, hend=1, eos=0]
             [HTTP/2] [1] <- FRAME[DATA, len=5, eos=1, padlen=0]
             [HTTP/2] [1] DATA, window=5/10485760
             [HTTP/2] [1] CLOSED
             [HTTP/2] [0] ingress: nw-in buffered 0
             [HTTP/2] [0] ingress: done
             [HTTP/2] [1] returning CLOSE
             [HTTP/2] handle_stream_close -> 0, 0
             [HTTP/2] [1] cf_recv(len=16384) -> 0, 0, window=-1/-1, connection \
                 1048575995/1048576000"
        )
    );
}

/// A POST: the body read for the session as it frames it, its last DATA
/// ending the stream, before the send's line.
#[test]
fn a_post_traces_its_body_read_as_c_does() {
    let reply: &[u8] = b"S 100\nH 1 1\n:status: 201\n\n";
    let (ran, _) = h2_run(&[reply], |o| {
        o.upload = crate::options::UploadSource::Bytes(
            curl_alloc::TryArc::try_new(b"abc".to_vec()).unwrap(),
        );
        o.method = Method::Post;
    });
    assert_eq!(ran.result, Ok(()), "{:?}", ran.seen.text());
    let lines = h2_lines(&ran.seen);
    let from = lines
        .iter()
        .position(|l| l.contains("submit ->"))
        .expect("submitted");
    assert_eq!(
        lines[from..from + 5],
        expect(
            "[HTTP/2] [1] submit -> 0, 147
             [HTTP/2] [1] -> FRAME[HEADERS, len=166, hend=1, eos=0]
             [HTTP/2] [1] req_body_read(len=16384) eos=1 -> 3, 0
             [HTTP/2] [1] -> FRAME[DATA, len=3, eos=1, padlen=0]
             [HTTP/2] [1] cf_send(len=147) -> 0, 147, eos=1, h2 windows 2147483647-2147483647 \
                 (stream-conn), buffers 0-0 (stream-conn)"
        )
    );
}

/// A stream the server resets: its frame, its close with the code's
/// name, and the read failing, each line of the failure as C traces it.
#[test]
fn a_reset_traces_the_stream_s_end_and_the_failed_read() {
    let (ran, _) = h2_run(&[b"S 100\nR 1 2\n"], |_| {});
    assert_eq!(ran.result, Err(ErrorKind::Http2Stream));
    let lines = h2_lines(&ran.seen);
    let from = lines
        .iter()
        .position(|l| l.contains("RST_STREAM"))
        .expect("read");
    assert_eq!(
        lines[from..],
        expect(
            "[HTTP/2] [1] <- FRAME[RST_STREAM, len=4, flags=0, error=2]
             [HTTP/2] [1] RESET: INTERNAL_ERROR (err 2)
             [HTTP/2] [0] ingress: nw-in buffered 0
             [HTTP/2] [0] ingress: done
             [HTTP/2] [1] returning CLOSE
             [HTTP/2] [1] stream_recv(len=16384) -> 92, 0
             [HTTP/2] [1] cf_recv(len=16384) -> 92, 0, window=-1/-1, connection \
                 1048576000/1048576000"
        )
    );
}

/// A server going away with an error before the stream is served: its
/// GOAWAY, the stream refused by it, said with the code it closed with,
/// and a limit the server never said, unlimited, told as changed from
/// C's guess of 100.
#[test]
fn a_goaway_traces_the_refused_stream() {
    let (ran, _) = h2_run(&[b"S\nG 0 2\n"], |_| {});
    assert_eq!(ran.result, Err(ErrorKind::Http2Stream));
    let lines = h2_lines(&ran.seen);
    let from = lines
        .iter()
        .position(|l| l.contains("<- FRAME[SETTINGS"))
        .expect("read");
    assert_eq!(
        lines[from..from + 9],
        expect(
            "[HTTP/2] [0] <- FRAME[SETTINGS, len=0]
             [HTTP/2] [0] MAX_CONCURRENT_STREAMS: 4294967295
             [HTTP/2] [0] ENABLE_PUSH: TRUE
             [HTTP/2] [0] notify MAX_CONCURRENT_STREAMS: 4294967295
             [HTTP/2] [0] <- FRAME[GOAWAY, error=2, reason='', last_stream=0]
             [HTTP/2] [1] RESET: REFUSED_STREAM (err 7)
             [HTTP/2] [0] ingress: nw-in buffered 0
             [HTTP/2] [0] ingress: done
             [HTTP/2] [1] returning CLOSE"
        )
    );
}

/// The connection's goodbye, on the multi's internal trace: its GOAWAY,
/// with C's debug data, then its end, once (`cf_h2_shutdown`,
/// `Curl_cshutdn_try_once_idx`).
#[test]
fn a_shutdown_traces_its_goaway_and_its_end_once() {
    #[derive(Clone, Default)]
    struct Written(Arc<Mutex<Vec<u8>>>);
    impl crate::handler::TextSink for Written {
        fn write(&self, text: &[u8]) {
            self.0.lock().unwrap().extend_from_slice(text);
        }
    }
    let reply: &[u8] = b"S 100\nH 1 0\n:status: 200\n\nD 1 2 1\nok";
    let talk = Conversation::replies(&[reply], false).per_send();
    let mut m = serving(Peer::Accepts, &[&talk]);
    let components = Components::new().unwrap();
    components.set(Component::Http2, Level::Info);
    let written = Written::default();
    m.trace_internally_to(components, Handler::text(written.clone()).unwrap());
    let ran = get_with(&mut m, tracing(), "/", talk.clone(), |o| {
        o.http.version = HttpVersion::Http2Prior;
        o.limits.reuse.forbid = true;
    });
    assert_eq!(ran.result, Ok(()), "{:?}", ran.seen.text());
    let text = String::from_utf8(written.0.lock().unwrap().clone()).unwrap();
    let said: Vec<&str> = text.lines().filter(|l| l.contains("[HTTP/2]")).collect();
    assert_eq!(
        said,
        [
            "* [HTTP/2] [0] -> FRAME[GOAWAY, error=0, reason='shutdown', last_stream=0]",
            "* [HTTP/2] shut down successfully",
        ],
        "{text}"
    );
}
