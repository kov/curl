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

/// A verbose request by prior knowledge, as `h2_run` makes it, the
/// multi's lines traced too: its state lines and its note that a
/// connection changed, with how the transfer ended.
fn h2_states(replies: &[&[u8]]) -> (Result<(), ErrorKind>, Vec<String>) {
    let talk = Conversation::replies(replies, false).per_send();
    let mut m = serving(Peer::Accepts, &[&talk]);
    let e = tracing();
    e.components().unwrap().configure(b"http/2,multi");
    let ran = get_with(&mut m, e, "/x", talk.clone(), |o| {
        o.http.version = HttpVersion::Http2Prior;
    });
    (ran.result, multi_states(&ran.seen))
}

/// The multi's state lines of `seen` and its note that a connection
/// changed, and what the server's limit on streams and a GOAWAY said.
fn multi_states(seen: &Seen) -> Vec<String> {
    seen.text()
        .into_iter()
        .map(|l| l.trim_end().to_owned())
        .filter(|l| {
            l.starts_with("[MULTI] [") && (l.contains("] -> [") || l.contains("multi changed"))
                || l.contains("MAX_CONCURRENT_STREAMS")
                || l.contains("GOAWAY")
        })
        .collect()
}

/// A server's stream limit other than the one last said is news to the
/// multi, which hears it as the transfer's next step starts, after the
/// connection found to multiplex was, in DID: C's lines, as the C build
/// says them against nghttpd's `-m 50` (`on_frame_recv`'s
/// `Curl_multi_connchanged`, `multi_runsingle`).
#[test]
fn a_new_stream_limit_is_said_as_the_next_step_starts() {
    let reply: &[u8] = b"S 50\nH 1 0\n:status: 200\ncontent-length: 2\n\nD 1 2 1\nok";
    let (result, states) = h2_states(&[reply]);
    assert_eq!(result, Ok(()));
    let changed = "multi changed, check CONNECT_PEND queue";
    assert_eq!(
        states,
        [
            "[MULTI] [INIT] -> [SETUP]".to_owned(),
            "[MULTI] [SETUP] -> [CONNECT]".to_owned(),
            "[MULTI] [CONNECT] -> [CONNECTING]".to_owned(),
            "[MULTI] [CONNECTING] -> [PROTOCONNECT]".to_owned(),
            "[MULTI] [PROTOCONNECT] -> [DO]".to_owned(),
            "[MULTI] [DO] -> [DID]".to_owned(),
            format!("[MULTI] [DID] {changed}"),
            "[MULTI] [DID] -> [PERFORMING]".to_owned(),
            "[HTTP/2] [0] MAX_CONCURRENT_STREAMS: 50".to_owned(),
            "[HTTP/2] [0] notify MAX_CONCURRENT_STREAMS: 50".to_owned(),
            "[MULTI] [PERFORMING] -> [DONE]".to_owned(),
            format!("[MULTI] [DONE] {changed}"),
            "[MULTI] [DONE] -> [COMPLETED]".to_owned(),
            "[MULTI] [COMPLETED] -> [MSGSENT]".to_owned(),
        ]
    );
    // The limit C guesses is no news.
    let reply: &[u8] = b"S 100\nH 1 0\n:status: 200\ncontent-length: 2\n\nD 1 2 1\nok";
    let (result, states) = h2_states(&[reply]);
    assert_eq!(result, Ok(()));
    let said = states.iter().filter(|l| l.contains(changed)).count();
    assert_eq!(said, 1, "{states:#?}");
}

/// A GOAWAY is news to the multi too (`on_frame_recv`'s
/// `Curl_multi_connchanged`), but not to the transfer it fails, which
/// ends in the step that read it, as C's does in that call
/// (`is_finished`). The C build says the same against a server answering
/// with a GOAWAY alone.
#[test]
fn a_goaway_failing_the_transfer_is_no_news_to_it() {
    let (result, states) = h2_states(&[b"S 100\nG 0 2\n"]);
    assert_eq!(result, Err(ErrorKind::Http2Stream));
    assert_eq!(
        states[states.len() - 5..],
        [
            "[HTTP/2] [0] MAX_CONCURRENT_STREAMS: 100",
            "[HTTP/2] [0] <- FRAME[GOAWAY, error=2, reason='', last_stream=0]",
            "received GOAWAY, error=2, last_stream=0",
            "[MULTI] [PERFORMING] -> [COMPLETED]",
            "[MULTI] [COMPLETED] -> [MSGSENT]",
        ],
        "{states:#?}"
    );
}

/// The connection's goodbye, on the multi's internal trace: its GOAWAY,
/// with C's debug data, then its end, once (`cf_h2_shutdown`,
/// `Curl_cshutdn_try_once_idx`).
#[test]
fn a_shutdown_traces_its_goaway_and_its_end_once() {
    #[derive(Clone, Default)]
    struct Written(Arc<Lock<Vec<u8>>>);
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

/// A connection whose frames come a few bytes a read is read in one
/// receive of the step, however many reads that takes, until the stream
/// ends or a read would block: C's `h2_progress_ingress` stops only at a
/// buffer's worth of bytes, never at a count of reads, and `cf_h2_recv`
/// says nothing read, so `sendrecv_dl` makes it once a step (pytest
/// `test_04_04` h2: a thousand reads and more in one `cf_recv`).
#[test]
fn a_step_reads_frames_however_many_reads_they_take() {
    const FRAMES: usize = 20;
    let mut reply = b"S 100\nH 1 0\n:status: 200\n\n".to_vec();
    for i in 0..FRAMES {
        let end = u8::from(i == FRAMES - 1);
        reply.extend_from_slice(format!("D 1 1 {end}\nx").as_bytes());
    }
    // A frame a read: nine bytes each.
    let per_read = std::num::NonZeroUsize::new(9).unwrap();
    let talk = Conversation::replies(&[&reply], false)
        .per_send()
        .giving(per_read);
    let mut m = serving(Peer::Accepts, &[&talk]);
    let ran = get_with(&mut m, tracing(), "/x", talk.clone(), |o| {
        o.http.version = HttpVersion::Http2Prior;
    });
    assert_eq!(ran.result, Ok(()), "{:?}", ran.seen.text());
    let lines = h2_lines(&ran.seen);
    let receives: Vec<&String> = lines.iter().filter(|l| l.contains("cf_recv(")).collect();
    assert_eq!(
        receives,
        [
            "[HTTP/2] [1] cf_recv(len=16384) -> 0, 0, window=-1/-1, connection \
          1048575980/1048576000"
        ],
        "{lines:#?}"
    );
    let reads = lines.iter().filter(|l| l.contains("ingress: read")).count();
    assert_eq!(reads, reply.len().div_ceil(9), "{lines:#?}");
    assert!(reads > 11);
}

/// Over TLS with ALPN agreeing `h2`, the session is made as the HTTPS
/// connect filter's attempt wins, its filter in the chains the connect
/// traces, and the request asks it what was agreed.
#[test]
fn alpn_agreeing_h2_makes_the_session_as_the_connection_is_set_up() {
    use crate::libraries::Library;
    use crate::tls::fake::{self, FakeTls, WELCOME};
    static FAKE: FakeH2 = FakeH2;
    let backend: &'static FakeTls = Box::leak(Box::new(FakeTls::agreeing().unwrap()));
    let libraries = SharedLibraries::new(Libraries {
        tls: Some(Library::Static(backend)),
        h2: Some(&FAKE as &dyn crate::http2::Http2),
        ..Libraries::NONE
    })
    .unwrap();
    let reply = b"S 100\nH 1 0\n:status: 200\ncontent-length: 5\n\nD 1 5 1\nhello";
    let response = fake::records(reply).unwrap();
    let talk = Conversation::replies(&[WELCOME, &response], false).per_send();
    let mut m = serving(Peer::Accepts, &[&talk]);
    let mut e = Easy::new();
    e.set_libraries(libraries);
    let c = Components::new().unwrap();
    c.configure(b"all");
    e.set_components(Some(c));
    let url = format!("https://127.0.0.1:{PORT}/");
    let ran = get_with(&mut m, e, "/", talk.clone(), |o| {
        o.set_url(Some(url.as_bytes())).unwrap();
        o.output.verbose = true;
    });
    assert_eq!(ran.result, Ok(()), "{:?}", ran.seen.text());
    let lines: Vec<String> = ran
        .seen
        .text()
        .into_iter()
        .map(|l| l.trim_end().to_owned())
        .filter(|l| {
            [
                "query ALPN",
                "connected [",
                "reduced to [",
                "created h2 session",
            ]
            .iter()
            .any(|n| l.contains(n))
                || l.ends_with("] using HTTP/2")
        })
        .collect();
    // C's, from pytest test_02_08 (h2, `CURL_DEBUG=all`), with its
    // connect's SETTINGS between the first three and the chain's. The
    // fake's chain has one `[DNS]`, its resolve being one filter.
    assert_eq!(
        lines,
        expect(
            "[0-0] [SETUP] query ALPN
             [0-0] [SSL] query ALPN: returning 'h2'
             [0-0] [HTTP/2] [0] created h2 session
             [0-0] [MULTI] [CONNECTING] connected \
                 [0][DNS][HTTPS-CONNECT][HTTP/2][SETUP][SSL][HAPPY-EYEBALLS][TCP]
             [0-0] [MULTI] [CONNECTING] reduced to [0][HTTP/2][SSL][TCP]
             [0-0] [HTTP/2] query ALPN
             [0-0] [SSL] query ALPN: returning 'h2'
             [0-0] using HTTP/2"
        ),
        "{lines:#?}"
    );
}

/// A POST of `body` by prior knowledge, its handle tracing the HTTP/2
/// filter and the socket's sends, `talk` the server: the sends the
/// socket was given in order, what each was given and what it took, in
/// runs each a send or a receive of the request's ends, at the filter's
/// `cf_send` or `cf_recv` line; and the run.
fn h2_upload(body: &[u8], talk: Conversation) -> (Vec<Vec<(usize, usize)>>, Ran) {
    let mut m = serving(Peer::Accepts, &[&talk]);
    let mut e = tracing();
    let c = Components::new().unwrap();
    c.configure(b"http/2,tcp");
    e.set_components(Some(c));
    let body = body.to_vec();
    let ran = get_with(&mut m, e, "/up", talk.clone(), |o| {
        o.http.version = HttpVersion::Http2Prior;
        o.upload = crate::options::UploadSource::Bytes(curl_alloc::TryArc::try_new(body).unwrap());
        o.method = Method::Post;
    });
    assert_eq!(ran.result, Ok(()), "{:?}", ran.seen.text());
    let mut runs = vec![Vec::new()];
    for line in ran.seen.text() {
        if let Some(rest) = line.split("[TCP] send(len=").nth(1) {
            // "<given>) -> <code>, <taken>"
            let (given, rest) = rest.split_once(") -> ").unwrap();
            let taken = rest.split(", ").nth(1).unwrap().trim();
            let send = (given.parse().unwrap(), taken.parse().unwrap());
            runs.last_mut().unwrap().push(send);
        } else if line.contains("[HTTP/2] [1] cf_send(") || line.contains("[HTTP/2] [1] cf_recv(") {
            runs.push(Vec::new());
        }
    }
    runs.retain(|r| !r.is_empty());
    (runs, ran)
}

/// The DATA payloads in what the fake server was sent, in order.
fn data_sent(request: &[u8]) -> Vec<u8> {
    let mut payload = Vec::new();
    let mut at = 0;
    while let Some(i) = request[at..].windows(4).position(|w| w == b"D 1 ") {
        let start = at + i;
        let nl = start + request[start..].iter().position(|&b| b == b'\n').unwrap();
        let line = std::str::from_utf8(&request[start..nl]).unwrap();
        let n: usize = line.split(' ').nth(2).unwrap().parse().unwrap();
        payload.extend_from_slice(&request[nl + 1..nl + 1 + n]);
        at = nl + 1 + n;
    }
    payload
}

/// The connection is sent the session's frames a 16 KiB chunk at a
/// time, the chunks cut across the frames, and what is left of the last
/// chunk once the session frames no more: C's `nw_out_writer` passes its
/// output buffer of one chunk on as it fills, and `nw_out_flush` the
/// rest (`Curl_cf_send_bufq`, `H2_NW_SEND_CHUNKS`). C's against nghttpd
/// sends 16384 bytes at a time of nghttp2's 16393-byte DATA frames.
#[test]
fn a_body_goes_to_the_connection_a_chunk_at_a_time() {
    let body = vec![b'.'; 200_000];
    let reply: &[u8] = b"S 100\nH 1 1\n:status: 201\n\n";
    let talk = Conversation::replies(&[reply], false).per_send();
    let (runs, ran) = h2_upload(&body, talk);
    for run in &runs {
        assert!(run.iter().all(|(given, taken)| given == taken), "{runs:?}");
        let (last, whole) = run.split_last().unwrap();
        assert!(whole.iter().all(|&(n, _)| n == 16384), "{runs:?}");
        assert!(last.0 <= 16384, "{runs:?}");
    }
    let chunks = runs.iter().flatten().filter(|&&(n, _)| n == 16384).count();
    assert!(chunks >= body.len() / 16384, "{runs:?}");
    assert_eq!(data_sent(&ran.request), body);
}

/// A connection that takes less than a chunk at a time is sent the rest
/// of the chunk each time, never past its end: C's `Curl_bufq_pass`
/// looks at the first chunk alone.
#[test]
fn a_chunk_goes_whole_before_the_next_however_little_a_send_takes() {
    let body = vec![b'.'; 100_000];
    let reply: &[u8] = b"S 100\nH 1 1\n:status: 201\n\n";
    let takes = std::num::NonZeroUsize::new(5000).unwrap();
    let talk = Conversation::replies(&[reply], false)
        .per_send()
        .taking(takes);
    let (runs, ran) = h2_upload(&body, talk);
    let sends: Vec<(usize, usize)> = runs.into_iter().flatten().collect();
    let chunk = [(16384, 5000), (11384, 5000), (6384, 5000), (1384, 1384)];
    assert_eq!(sends[..4], chunk, "{sends:?}");
    assert_eq!(sends[4..8], chunk, "{sends:?}");
    assert_eq!(data_sent(&ran.request), body);
}

/// A connection that blocks holds what the session framed: the chunk
/// waits, traced as C's flush traces it, and the frame that did not fit
/// waits in the session, sent first once the connection takes again, no
/// byte of the body lost or sent twice.
#[test]
fn a_blocked_connection_keeps_the_frames_in_order() {
    let body = vec![b'.'; 100_000];
    let reply: &[u8] = b"S 100\nH 1 1\n:status: 201\n\n";
    let talk = Conversation::replies(&[reply], false)
        .per_send()
        .stalling_sends_after(2, 3);
    let (_, ran) = h2_upload(&body, talk);
    let lines = h2_lines(&ran.seen);
    assert!(
        lines
            .iter()
            .any(|l| l == "[HTTP/2] flush nw send buffer(16384) -> EAGAIN"),
        "{lines:#?}"
    );
    assert_eq!(data_sent(&ran.request), body);
}

/// A POST of `body` by prior knowledge over `talk`, added to a multi on
/// `clock`, its handle tracing the HTTP/2 filter: the multi, the
/// transfer and what it saw.
fn h2_upload_on(
    clock: &ManualClock,
    body: &[u8],
    talk: &Conversation,
) -> (Multi, crate::multi::TransferId, Seen) {
    let mut m = serving_on(clock.clone(), Peer::Accepts, &[talk]);
    let mut e = tracing();
    let seen = Seen::default();
    let o = e.options_mut();
    o.set_url(Some(format!("http://127.0.0.1:{PORT}/up").as_bytes()))
        .unwrap();
    o.output.verbose = true;
    o.limits.total = crate::time::TimeLimit::from_millis(100_000);
    o.callbacks.write = Some(Handler::write(seen.clone()).unwrap());
    o.callbacks
        .rare
        .set(
            |r| &mut r.debug,
            Some(Handler::debug(seen.clone()).unwrap()),
        )
        .unwrap();
    o.http.version = HttpVersion::Http2Prior;
    o.upload =
        crate::options::UploadSource::Bytes(curl_alloc::TryArc::try_new(body.to_vec()).unwrap());
    o.method = Method::Post;
    let id = m.add(Box::new(e), (), &mut NoEvents).unwrap();
    (m, id, seen)
}

/// One wait of at most a second, and one perform.
fn round(m: &mut Multi) {
    let poll = crate::multi::WaitMode::Poll;
    m.wait(&mut [], Duration::from_secs(1), poll, &mut NoEvents)
        .unwrap();
    m.perform(&mut NoEvents).unwrap();
}

/// The sends with stream 1's send window shut, as the filter's
/// `cf_send` lines say.
fn shut_sends(seen: &Seen) -> usize {
    seen.text()
        .iter()
        .filter(|l| l.contains("[HTTP/2] [1] cf_send(") && l.contains("h2 windows 0-"))
        .count()
}

/// A stream whose send window the server shut waits to read the
/// server's update, not to write: C takes the transfer's wish to write
/// out of its pollset while the window is nothing (`cf_h2_adjust_pollset`'s
/// `s_exhaust`), so a full body buffer is not offered more again and
/// again, each time taking none. The C build against `nghttpd -w 0` sends
/// once a second, its wait timing out each time; a transfer that waits to
/// write spins, and the fake clock never moves. The update opens the
/// window, and the body goes whole.
#[test]
fn a_shut_send_window_waits_for_the_update_not_the_socket() {
    let body = vec![b'.'; 300_000];
    let settings: &[u8] = b"S 100 0\n";
    let update: &[u8] = b"U 1 1000000\n";
    let reply: &[u8] = b"H 1 1\n:status: 201\n\n";
    let talk = Conversation::replies(&[settings, update, reply], false)
        .per_send()
        .held();
    talk.allow(1);
    let clock = ManualClock::new().unwrap();
    let (mut m, id, seen) = h2_upload_on(&clock, &body, &talk);
    let start = clock.now();
    let mut rounds = 0;
    while clock.now().since(start) < Duration::from_secs(5) && rounds < 100 {
        round(&mut m);
        rounds += 1;
    }
    // A round a second, its wait timing out, and a send in each.
    assert!(rounds <= 7, "{rounds} rounds in 5 s of a shut window");
    let sends = shut_sends(&seen);
    assert!(
        (1..=8).contains(&sends),
        "{sends} sends with the window shut"
    );
    assert!(data_sent(&talk.received()).len() < body.len());
    talk.allow(2);
    let opened = clock.now();
    let mut rounds = 0;
    while data_sent(&talk.received()).len() < body.len() {
        assert!(rounds < 100, "the body did not go once the window opened");
        round(&mut m);
        rounds += 1;
    }
    // The update read, the transfer waits to write again at once: no
    // wait timed out.
    assert_eq!(clock.now(), opened, "the opened window waited");
    talk.allow(3);
    let result = drive_to_completion(&mut m, id, &mut NoEvents).unwrap();
    assert_eq!(result, Ok(()), "{:#?}", seen.text());
    assert_eq!(data_sent(&talk.received()), body);
}

/// A body the stream's buffer has no room for is taken none of, which C
/// says is `CURLE_AGAIN` (81): `Curl_bufq_write` into a full `sendbuf`
/// fails so, and `cf_h2_send` returns it, traced on both its lines. The
/// C build against `nghttpd -w 0` traces `cf_body_send(len=65536) -> 81,
/// 0, eos=0` and its `cf_send` line `-> 81, 0`.
#[test]
fn a_full_body_buffer_traces_again() {
    let body = vec![b'.'; 300_000];
    let settings: &[u8] = b"S 100 0\n";
    let talk = Conversation::replies(&[settings], false).per_send();
    let clock = ManualClock::new().unwrap();
    let (mut m, _, seen) = h2_upload_on(&clock, &body, &talk);
    for _ in 0..3 {
        round(&mut m);
    }
    let lines = h2_lines(&seen);
    let full = lines
        .iter()
        .position(|l| l == "[HTTP/2] [1] cf_body_send(len=65536) -> 81, 0, eos=0")
        .unwrap_or_else(|| panic!("{lines:#?}"));
    assert!(
        lines[full + 1].starts_with("[HTTP/2] [1] cf_send(len=65536) -> 81, 0, eos=0, "),
        "{lines:#?}"
    );
    assert!(
        !lines
            .iter()
            .any(|l| l.contains("cf_body_send(len=65536) -> 0, 0,")),
        "{lines:#?}"
    );
}

/// An upload of `body` to `path`, with the fake library, verbose.
fn upload_handle(body: &[u8], path: &str) -> (Easy, Seen) {
    let mut e = tracing();
    let seen = Seen::default();
    let o = e.options_mut();
    o.set_url(Some(format!("http://127.0.0.1:{PORT}{path}").as_bytes()))
        .unwrap();
    o.output.verbose = true;
    o.limits.total = crate::time::TimeLimit::from_millis(100_000);
    o.callbacks.write = Some(Handler::write(seen.clone()).unwrap());
    o.callbacks
        .rare
        .set(
            |r| &mut r.debug,
            Some(Handler::debug(seen.clone()).unwrap()),
        )
        .unwrap();
    o.http.version = HttpVersion::Http2Prior;
    o.upload =
        crate::options::UploadSource::Bytes(curl_alloc::TryArc::try_new(body.to_vec()).unwrap());
    o.method = Method::Post;
    (e, seen)
}

/// A WINDOW_UPDATE for a stream whose body is buffered, read by a
/// sibling's step, has the session resume the stream, and does not mark
/// the stream's transfer to run again: C marks it only when it has none
/// of its body buffered (`on_stream_frame`), so the multi's next wait
/// waits. The second transfer reads the updates for the first's stream
/// after the first ran in the pass; marked, the first would make the
/// wait return at once, a pass over every transfer for nothing.
#[test]
fn a_window_update_read_by_a_sibling_wakes_no_one_with_a_body_held() {
    let body = vec![b'.'; 300_000];
    let up: &[u8] = b"U 1 16384\n";
    // The first's own step reads the first updates; a later one comes
    // with a send of the first's, which the second's step reads.
    let start: [&[u8]; 3] = [b"S 100 16384\n", b"", b""];
    let replies: Vec<&[u8]> = start.into_iter().chain([up; 8]).collect();
    let talk = Conversation::replies(&replies, false).per_send().held();
    talk.allow(3);
    let clock = ManualClock::new().unwrap();
    let mut m = serving_on(clock.clone(), Peer::Accepts, &[&talk]);
    let (a, sa) = upload_handle(&body, "/a");
    m.add(Box::new(a), (), &mut NoEvents).unwrap();
    // The first is under way, its window shut, before the second joins.
    for _ in 0..3 {
        round(&mut m);
    }
    let (b, sb) = upload_handle(&body, "/b");
    m.add(Box::new(b), (), &mut NoEvents).unwrap();
    talk.allow(11);
    let updates = |s: &Seen| {
        s.text()
            .iter()
            .filter(|l| l.contains("[1] <- FRAME[WINDOW_UPDATE"))
            .count()
    };
    let mut read_by_b = 0;
    for _ in 0..4 {
        round(&mut m);
        let now = updates(&sb);
        if now > read_by_b {
            assert_ne!(
                m.timeout(),
                Some(Duration::ZERO),
                "a window update woke its stream's transfer"
            );
            read_by_b = now;
        }
    }
    assert!(read_by_b > 0, "{:#?}\n{:#?}", sa.text(), sb.text());
    // Resumed, the stream's body went on, whichever transfer framed it:
    // four frames went before the window was shut.
    let framed = [&sa, &sb]
        .iter()
        .flat_map(|s| s.text())
        .filter(|l| l.contains("[1] -> FRAME[DATA"))
        .count();
    assert!(framed > 4, "the stream was not resumed: {framed} frames");
}

/// A session with nothing it wants to write is not asked to: C sends
/// only while `nghttp2_session_want_write` says so (`h2_progress_egress`).
/// With the stream's window shut and its buffer full, each pass's
/// sends and reads ask nothing of the session; once the update opens
/// the window, it is asked again.
#[test]
fn a_session_that_wants_to_write_nothing_is_not_asked_to_send() {
    let body = vec![b'.'; 300_000];
    let settings: &[u8] = b"S 100 0\n";
    let update: &[u8] = b"U 1 1000000\n";
    let talk = Conversation::replies(&[settings, update], false)
        .per_send()
        .held();
    talk.allow(1);
    let clock = ManualClock::new().unwrap();
    let (mut m, _, seen) = h2_upload_on(&clock, &body, &talk);
    for _ in 0..3 {
        round(&mut m);
    }
    assert!(shut_sends(&seen) > 0, "{:#?}", seen.text());
    let before = crate::http2::fake::calls().send;
    for _ in 0..3 {
        round(&mut m);
    }
    assert_eq!(
        crate::http2::fake::calls().send,
        before,
        "asked with nothing to write"
    );
    talk.allow(2);
    round(&mut m);
    assert!(
        crate::http2::fake::calls().send > before,
        "not asked once the window opened"
    );
}

/// A body its stream's full buffer takes none of resumes nothing: C's
/// `cf_h2_body_send` returns the buffer's `CURLE_AGAIN` before it calls
/// `nghttp2_session_resume_data`. A part of it the buffer took does.
#[test]
fn a_body_a_full_buffer_takes_none_of_resumes_nothing() {
    let body = vec![b'.'; 300_000];
    let settings: &[u8] = b"S 100 0\n";
    let update: &[u8] = b"U 1 1000000\n";
    let talk = Conversation::replies(&[settings, update], false)
        .per_send()
        .held();
    talk.allow(1);
    let clock = ManualClock::new().unwrap();
    let (mut m, _, seen) = h2_upload_on(&clock, &body, &talk);
    for _ in 0..3 {
        round(&mut m);
    }
    let full = |s: &Seen| {
        s.text()
            .iter()
            .filter(|l| l.contains("cf_body_send(len=65536) -> 81, 0,"))
            .count()
    };
    let (before, fulls) = (crate::http2::fake::calls().resume, full(&seen));
    for _ in 0..3 {
        round(&mut m);
    }
    assert!(full(&seen) > fulls, "{:#?}", seen.text());
    assert_eq!(
        crate::http2::fake::calls().resume,
        before,
        "resumed with none taken"
    );
    talk.allow(2);
    for _ in 0..3 {
        round(&mut m);
    }
    assert!(
        crate::http2::fake::calls().resume > before,
        "not resumed once taken"
    );
}

/// The windows a send's and a receive's last lines give are asked of
/// the session only when the lines are traced, as C's `CURL_TRC_CF` asks
/// for them: the same upload, untraced, asks for two send windows fewer
/// (the stream's and the connection's) for each `cf_send` line the
/// traced one wrote, and three receive windows fewer (the stream's two
/// and the connection's) for each `cf_recv` line. What is left is what
/// its pollsets ask (`cf_h2_adjust_pollset`).
#[test]
fn a_stream_s_windows_are_asked_only_to_trace_them() {
    let asked = |traced: bool| {
        let body = vec![b'.'; 300_000];
        let settings: &[u8] = b"S 100 0\n";
        let talk = Conversation::replies(&[settings], false).per_send();
        let clock = ManualClock::new().unwrap();
        let mut m = serving_on(clock.clone(), Peer::Accepts, &[&talk]);
        let (mut e, seen) = upload_handle(&body, "/up");
        if !traced {
            e.set_components(None);
        }
        m.add(Box::new(e), (), &mut NoEvents).unwrap();
        for _ in 0..3 {
            round(&mut m);
        }
        let calls = crate::http2::fake::calls;
        let before = (calls(), lines(&seen, "cf_send("), lines(&seen, "cf_recv("));
        for _ in 0..3 {
            round(&mut m);
        }
        (
            calls().send_windows - before.0.send_windows,
            calls().recv_windows - before.0.recv_windows,
            lines(&seen, "cf_send(") - before.1,
            lines(&seen, "cf_recv(") - before.2,
        )
    };
    let (send, recv, sends, recvs) = asked(true);
    let untraced = asked(false);
    assert_eq!((untraced.2, untraced.3), (0, 0));
    assert!(sends > 0 && recvs > 0, "{sends} sends, {recvs} receives");
    assert_eq!(
        send - untraced.0,
        2 * sends,
        "{send} send windows traced, {untraced:?}"
    );
    assert_eq!(
        recv - untraced.1,
        3 * recvs,
        "{recv} receive windows traced, {untraced:?}"
    );
}

/// The filter's lines of stream 1 a run traced that start with `what`.
fn lines(seen: &Seen, what: &str) -> usize {
    seen.text()
        .iter()
        .filter(|l| l.contains(&format!("[HTTP/2] [1] {what}")))
        .count()
}

/// A wait makes each transfer's pollset twice: once to count the
/// sockets its trace says, once to poll them. An upload wanting to send
/// asks the session for its two send windows each time its pollset is
/// made (`cf_h2_adjust_pollset`), so one wait asks four.
#[test]
fn a_wait_makes_each_pollset_twice() {
    let body = vec![b'.'; 300_000];
    let settings: &[u8] = b"S 100 16384\n";
    let talk = Conversation::replies(&[settings], false).per_send();
    let clock = ManualClock::new().unwrap();
    let mut m = serving_on(clock.clone(), Peer::Accepts, &[&talk]);
    let (mut e, _) = upload_handle(&body, "/up");
    // Unverbose: no pollset is made to be traced.
    e.set_components(None);
    e.options_mut().output.verbose = false;
    m.add(Box::new(e), (), &mut NoEvents).unwrap();
    for _ in 0..3 {
        round(&mut m);
    }
    let before = crate::http2::fake::calls().send_windows;
    let poll = crate::multi::WaitMode::Poll;
    m.wait(&mut [], Duration::from_secs(1), poll, &mut NoEvents)
        .unwrap();
    assert_eq!(crate::http2::fake::calls().send_windows - before, 4);
}

/// The response's head for a stream, read by a sibling's step, marks
/// the stream's transfer to run again, as C's `on_header` and
/// `on_stream_frame` do (`Curl_multi_mark_dirty`): the first transfer
/// ran earlier in the pass, so the multi's next wait returns at once for
/// it to take its response.
#[test]
fn a_head_read_by_a_sibling_wakes_its_transfer() {
    let body = vec![b'.'; 300_000];
    let up: &[u8] = b"U 1 16384\n";
    let head: &[u8] = b"H 1 0\n:status: 200\n\n";
    // As in the test above, the first's later sends bring replies the
    // second's step reads; the head comes with one of them.
    let start: [&[u8]; 3] = [b"S 100 16384\n", b"", b""];
    let mut replies: Vec<&[u8]> = start.into_iter().chain([up; 8]).collect();
    replies[9] = head;
    let talk = Conversation::replies(&replies, false).per_send().held();
    talk.allow(3);
    let clock = ManualClock::new().unwrap();
    let mut m = serving_on(clock.clone(), Peer::Accepts, &[&talk]);
    let (a, sa) = upload_handle(&body, "/a");
    m.add(Box::new(a), (), &mut NoEvents).unwrap();
    for _ in 0..3 {
        round(&mut m);
    }
    let (b, sb) = upload_handle(&body, "/b");
    m.add(Box::new(b), (), &mut NoEvents).unwrap();
    talk.allow(11);
    for _ in 0..4 {
        round(&mut m);
        if sb.text().iter().any(|l| l.contains("[1] <- FRAME[HEADERS")) {
            assert_eq!(
                m.timeout(),
                Some(Duration::ZERO),
                "a head read by a sibling left its transfer waiting"
            );
            return;
        }
    }
    panic!(
        "the second did not read the head: {:#?}\n{:#?}",
        sa.text(),
        sb.text()
    );
}

/// Two uploads on one connection, the first under way when the second
/// joins, told header fields as they come (`XF`). Each reply the server
/// has ready is read by the second transfer to look for it, the first to
/// look finding it not there yet: the first runs first in each pass, so
/// the second reads it after the first ran. The tenth, let go once the
/// second joins, opens the second's window and holds the first field of
/// the first's response's head; the eleventh, held until the test lets
/// it go, the head's end.
fn siblings_split_head() -> (Multi, Conversation, Seen, Seen) {
    let body = vec![b'.'; 300_000];
    let up: &[u8] = b"U 1 16384\n";
    let start: [&[u8]; 3] = [b"S 100 16384\nXF\n", b"", b""];
    let mut replies: Vec<&[u8]> = start.into_iter().chain([up; 8]).collect();
    replies[9] = b"U 3 1000000\nH 1 0\n:status: 200\n";
    replies[10] = b"\n";
    let talk = Conversation::replies(&replies, false)
        .per_send()
        .late_replies()
        .held();
    talk.allow(3);
    let clock = ManualClock::new().unwrap();
    let mut m = serving_on(clock.clone(), Peer::Accepts, &[&talk]);
    let (a, sa) = upload_handle(&body, "/a");
    m.add(Box::new(a), (), &mut NoEvents).unwrap();
    for _ in 0..3 {
        round(&mut m);
    }
    let (b, sb) = upload_handle(&body, "/b");
    m.add(Box::new(b), (), &mut NoEvents).unwrap();
    talk.allow(10);
    (m, talk, sa, sb)
}

/// How many lines `seen` traced holding `what`.
fn traced(seen: &Seen, what: &str) -> usize {
    seen.text().iter().filter(|l| l.contains(what)).count()
}

/// Rounds until the first field of stream 1's head is read, by the
/// second's step, the head's end not yet; panics if it is not.
fn read_split_field(m: &mut Multi, sa: &Seen, sb: &Seen) {
    for _ in 0..10 {
        round(m);
        if traced(sa, "[1] status: HTTP/2 200") > 0 {
            // The field came with the second's window update, which the
            // second's step read; the session is whole, the head's
            // frame not yet read.
            assert_eq!(traced(sb, "[3] <- FRAME[WINDOW_UPDATE"), 1);
            for seen in [sa, sb] {
                assert_eq!(traced(seen, "[1] <- FRAME[HEADERS"), 0);
                assert_eq!(traced(seen, "recv error"), 0, "{:#?}", seen.text());
            }
            return;
        }
        assert_eq!(traced(sb, "[3] <- FRAME[WINDOW_UPDATE"), 0);
    }
    panic!("the field was not read: {:#?}\n{:#?}", sa.text(), sb.text());
}

/// A field of the response's head for a stream, read by a sibling's
/// step before the head's end has come, marks the stream's transfer to
/// run again, as C's `on_header` does for each field of a head another
/// transfer reads (`Curl_multi_mark_dirty`): nghttp2 tells a block's
/// fields as they come, ahead of its end when the block is split across
/// reads. The first transfer ran earlier in the pass, so the multi's next
/// wait returns at once for it to take the field.
#[test]
fn a_head_s_field_read_by_a_sibling_wakes_its_transfer() {
    let (mut m, _talk, sa, sb) = siblings_split_head();
    read_split_field(&mut m, &sa, &sb);
    assert_eq!(
        m.timeout(),
        Some(Duration::ZERO),
        "a head's field read by a sibling left its transfer waiting"
    );
}

/// The end of the response's head for a stream, read by a sibling's
/// step after its fields were read and taken, marks the stream's
/// transfer to run again, as C's `on_stream_frame` does for a HEADERS
/// frame that ends a head (`Curl_multi_mark_dirty`): the head is done
/// only at its end, the stream not yet ended. The first transfer ran
/// earlier in the pass, so the multi's next wait returns at once for it
/// to take the head's end.
#[test]
fn a_head_s_end_read_by_a_sibling_wakes_its_transfer() {
    let (mut m, talk, sa, sb) = siblings_split_head();
    read_split_field(&mut m, &sa, &sb);
    // The end comes in the next pass, the first running in it for the
    // field and taking it before the second reads the end.
    talk.allow(11);
    round(&mut m);
    assert_eq!(traced(&sa, "[1] status: HTTP/2 200"), 1);
    assert_eq!(traced(&sa, "[1] <- FRAME[HEADERS"), 0, "{:#?}", sa.text());
    assert_eq!(traced(&sb, "[1] <- FRAME[HEADERS"), 1, "{:#?}", sb.text());
    assert_eq!(
        m.timeout(),
        Some(Duration::ZERO),
        "a head's end read by a sibling left its transfer waiting"
    );
}
