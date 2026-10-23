//! The write component's trace (`CURL_TRC_WRITE`): what C's writers say
//! of each piece of a response as it goes through them. Each expected
//! sequence is the C build's for the same response.

use super::*;
use crate::coding::{Coding, Decoder, Decoders, Sink};
use crate::components::Components;

/// A handle tracing its writers, and its header lines as `< line`.
fn writing() -> Easy {
    let mut e = Easy::new();
    let components = Components::new().unwrap();
    components.configure(b"write");
    e.set_components(Some(components));
    e
}

/// What a GET by `e` traced of its response: its header lines, each as
/// `< ` and the line, and the write component's lines.
fn written(e: Easy, reply: &[u8], set: impl FnOnce(&mut Options)) -> (Ran, Vec<String>) {
    let (mut m, talk, _) = server(&[reply], false);
    let ran = get_with(&mut m, e, "/", talk, set);
    let lines = ran
        .seen
        .0
        .lock()
        .unwrap()
        .iter()
        .filter_map(|(what, line)| {
            // A trailer's line ends inside its quotes.
            let line = String::from_utf8_lossy(line).replace("\r\n'", "\\r\\n'");
            match *what {
                "in" => Some(format!("< {line}").trim_end().to_owned()),
                "text" if line.starts_with("[WRITE] ") => Some(line.trim_end().to_owned()),
                _ => None,
            }
        })
        .collect();
    (ran, lines)
}

/// The lines of `lines`, trimmed, blank ones left out.
fn expect(lines: &str) -> Vec<String> {
    lines
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .map(str::to_owned)
        .collect()
}

/// A chunked body: the transfer decoder stacked at the header, each chunk
/// started and written, the trailer written as a header, and the whole
/// input written to the chunked writer at once.
#[test]
fn a_chunked_body_is_traced_through_its_writers_as_c() {
    let reply = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n\
        5\r\nhello\r\n7\r\n world\n\r\n0\r\nX-Trailer: yes\r\n\r\n";
    let (ran, lines) = written(writing(), reply, |_| {});
    assert_eq!(ran.result, Ok(()));
    assert_eq!(ran.seen.body(), b"hello world\n");
    let want = expect(
        "< HTTP/1.1 200 OK
        [WRITE] [OUT] wrote 17 header bytes, type=3 -> 17
        [WRITE] download_write header(type=c, blen=17) -> 0
        [WRITE] client_write(type=c, len=17) -> 0
        [WRITE] looking for transfer decoder: chunked
        [WRITE] added transfer decoder chunked -> 0
        < Transfer-Encoding: chunked
        [WRITE] header_collect pushed(type=1, len=28) -> 0
        [WRITE] [OUT] wrote 28 header bytes, type=3 -> 28
        [WRITE] download_write header(type=4, blen=28) -> 0
        [WRITE] client_write(type=4, len=28) -> 0
        <
        [WRITE] header_collect pushed(type=1, len=2) -> 0
        [WRITE] [OUT] wrote 2 header bytes, type=3 -> 2
        [WRITE] download_write header(type=4, blen=2) -> 0
        [WRITE] client_write(type=4, len=2) -> 0
        [WRITE] http_chunked, chunk start of 5 bytes
        [WRITE] [OUT] wrote 5 body bytes, type=1 -> 5
        [WRITE] download_write body(type=1, blen=5) -> 0
        [WRITE] http_chunked, write 5 body bytes, 0 bytes in chunk remain
        [WRITE] http_chunked, chunk start of 7 bytes
        [WRITE] [OUT] wrote 7 body bytes, type=1 -> 7
        [WRITE] download_write body(type=1, blen=7) -> 0
        [WRITE] http_chunked, write 7 body bytes, 0 bytes in chunk remain
        [WRITE] header_collect pushed(type=2, len=16) -> 0
        [WRITE] [OUT] wrote 16 header bytes, type=3 -> 16
        [WRITE] download_write header(type=44, blen=16) -> 0
        [WRITE] wrote trailer 'X-Trailer: yes\\r\\n'
        [WRITE] http_chunk, response complete
        [WRITE] client_write(type=1, len=43) -> 0
        [WRITE] xfer_write_resp(len=90, eos=0) -> 0
        [WRITE] [OUT] done
        [WRITE] client_flush() -> 0",
    );
    assert_eq!(lines, want);
}

/// Each byte, twice.
#[derive(Debug)]
struct Twice;

impl Decoder for Twice {
    fn decode(&mut self, input: &[u8], out: &mut dyn Sink) -> Result<(), ErrorKind> {
        let doubled: Vec<u8> = input.iter().flat_map(|&b| [b, b]).collect();
        out.write(&doubled)
    }
}

/// Each coding listed is looked for, and the decoder stacked for it named:
/// its own, `identity`'s, or the error writer's for one not undone; a
/// transfer coding not asked for is ignored.
#[test]
fn each_coding_is_looked_for_and_its_decoder_named_as_c() {
    let twice = || -> Result<Box<dyn Decoder>, ErrorKind> { Ok(Box::new(Twice)) };
    let undoing = || {
        let mut e = writing();
        e.set_decoders(Decoders::none().with(Coding::Gzip, twice));
        e
    };
    let reply = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip, chunked\r\n\r\n3\r\nabc\r\n0\r\n\r\n";
    let decoders = |lines: Vec<String>| -> Vec<String> {
        lines
            .into_iter()
            .filter(|l| l.contains("decoder"))
            .collect()
    };
    let (ran, lines) = written(undoing(), reply, |o| o.http.transfer_encoding = true);
    assert_eq!(ran.result, Ok(()));
    assert_eq!(
        decoders(lines),
        expect(
            "[WRITE] looking for transfer decoder: gzip
            [WRITE] added transfer decoder gzip -> 0
            [WRITE] looking for transfer decoder: chunked
            [WRITE] added transfer decoder chunked -> 0"
        )
    );
    // Not asked for, the list is refused as it is read.
    let (ran, lines) = written(undoing(), reply, |_| {});
    assert_eq!(ran.result, Err(ErrorKind::BadContentEncoding));
    assert_eq!(
        decoders(lines),
        expect(
            "[WRITE] looking for transfer decoder: gzip
            [WRITE] decoder not requested, ignored: gzip"
        )
    );
    let reply = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\
        Transfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n0\r\n\r\n";
    let (ran, lines) = written(writing(), reply, |_| {});
    assert_eq!(ran.result, Ok(()));
    assert_eq!(
        decoders(lines),
        expect(
            "[WRITE] looking for transfer decoder: chunked
            [WRITE] added transfer decoder chunked -> 0
            [WRITE] looking for transfer decoder: chunked
            [WRITE] ignoring duplicate 'chunked' decoder"
        )
    );
    let reply =
        b"HTTP/1.1 200 OK\r\nContent-Encoding: foo, identity\r\nContent-Length: 3\r\n\r\nabc";
    let (ran, lines) = written(writing(), reply, |o| {
        o.http.accept_encoding = Some(crate::coding::AcceptEncoding::All);
    });
    assert_eq!(ran.result, Err(ErrorKind::BadContentEncoding));
    assert_eq!(
        decoders(lines),
        expect(
            "[WRITE] looking for content decoder: foo
            [WRITE] added content decoder ce-error -> 0
            [WRITE] looking for content decoder: identity
            [WRITE] added content decoder identity -> 0"
        )
    );
    // A coding the handle has no decoder for is the error writer's, as a
    // coding built without is in C.
    let reply = b"HTTP/1.1 200 OK\r\nContent-Encoding: deflate\r\nContent-Length: 3\r\n\r\nabc";
    let (ran, lines) = written(undoing(), reply, |o| {
        o.http.accept_encoding = Some(crate::coding::AcceptEncoding::All);
    });
    assert_eq!(ran.result, Err(ErrorKind::BadContentEncoding));
    assert_eq!(
        decoders(lines),
        expect(
            "[WRITE] looking for content decoder: deflate
            [WRITE] added content decoder ce-error -> 0"
        )
    );
}

/// A chunked body that does not end in LF after its last CR says what it
/// saw instead, as C prints it: the byte in decimal between `0x` and `x`.
#[test]
fn a_bad_end_of_chunks_is_traced_as_c() {
    let reply = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n0\r\n\rX";
    let (ran, lines) = written(writing(), reply, |_| {});
    assert_eq!(ran.result, Err(ErrorKind::RecvError));
    let tail: Vec<String> = lines
        .into_iter()
        .skip_while(|l| !l.contains("chunk start"))
        .collect();
    assert_eq!(
        tail,
        expect(
            "[WRITE] http_chunked, chunk start of 3 bytes
            [WRITE] [OUT] wrote 3 body bytes, type=1 -> 3
            [WRITE] download_write body(type=1, blen=3) -> 0
            [WRITE] http_chunked, write 3 body bytes, 0 bytes in chunk remain
            [WRITE] http_chunk error, expected 0x0a, seeing 0x88x
            [WRITE] client_write(type=1, len=13) -> 56
            [WRITE] xfer_write_resp(len=60, eos=0) -> 56
            [WRITE] [OUT] done
            [WRITE] client_flush() -> 0"
        )
    );
}

/// Pauses twice, then takes the body.
#[derive(Clone, Default)]
struct PausesTwice(Arc<Mutex<u32>>);

impl WriteHandler for PausesTwice {
    fn write(&self, _: &mut TransferCx<'_>, _: &[u8]) -> Write {
        let mut calls = self.0.lock().unwrap();
        *calls += 1;
        if *calls <= 2 {
            Write::Pause
        } else {
            Write::Accepted
        }
    }
}

/// A body paused is buffered, flushed at the unpause and paused again,
/// then written, each step traced as C traces it.
#[test]
fn a_paused_body_is_traced_as_it_is_held_and_flushed() {
    let reply = b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nabc";
    let (mut m, _talk, _clock) = server(&[reply], false);
    let mut e = writing();
    let seen = Seen::default();
    let writer = PausesTwice::default();
    let o = e.options_mut();
    o.set_url(Some(format!("http://127.0.0.1:{PORT}/").as_bytes()))
        .unwrap();
    o.output.verbose = true;
    o.callbacks.write = Some(Handler::write(writer.clone()).unwrap());
    o.callbacks.debug = Some(Handler::debug(seen.clone()).unwrap());
    let id = m.add(Box::new(e), (), &mut NoEvents).unwrap();
    let mut unpaused = 0;
    let mut passes = 0;
    let result = loop {
        passes += 1;
        assert!(passes < 100, "the transfer does not end");
        m.perform(&mut NoEvents).unwrap();
        if let Some(done) = m.info_read() {
            break done.result;
        }
        let calls = *writer.0.lock().unwrap();
        if calls > unpaused {
            unpaused = calls;
            seen.0
                .lock()
                .unwrap()
                .push(("text", format!("== unpause after {calls}").into()));
            m.pause(id, PauseRequest::CONT, &mut NoEvents).unwrap();
        }
    };
    assert_eq!(result, Ok(()));
    let lines: Vec<String> = seen
        .text()
        .into_iter()
        .map(|l| l.trim_end().to_owned())
        .filter(|l| l.starts_with("[WRITE] [OUT]") || l.starts_with("=="))
        .collect();
    assert_eq!(
        lines,
        expect(
            "[WRITE] [OUT] wrote 3 body bytes, type=1 -> 268435457
            [WRITE] [OUT] PAUSE requested by client
            [WRITE] [OUT] paused, buffering 3 more bytes (0/67108864)
            == unpause after 1
            [WRITE] [OUT] flush
            [WRITE] [OUT] wrote 3 body bytes, type=1 -> 268435457
            [WRITE] [OUT] PAUSE requested by client
            == unpause after 2
            [WRITE] [OUT] flush
            [WRITE] [OUT] wrote 3 body bytes, type=1 -> 3
            [WRITE] [OUT] done"
        )
    );
}

/// Pauses at the blank line ending the head, once.
#[derive(Clone, Default)]
struct PausesAtTheEnd(Arc<Mutex<u32>>);

impl HeaderHandler for PausesAtTheEnd {
    fn header(&self, _: &mut TransferCx<'_>, line: &[u8], _: HeaderOrigin) -> Write {
        let mut calls = self.0.lock().unwrap();
        if line == b"\r\n" && *calls == 0 {
            *calls += 1;
            return Write::Pause;
        }
        Write::Accepted
    }
}

/// Paused at its head, a coded body waits at the gate before its decoder,
/// and goes through it at the unpause, each step traced as C traces it.
#[test]
fn a_coded_body_held_at_the_gate_is_traced_as_it_is_held_and_flushed() {
    let reply = b"HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nContent-Length: 3\r\n\r\nabc";
    let (mut m, _talk, _clock) = server(&[reply], false);
    let mut e = writing();
    let twice = || -> Result<Box<dyn Decoder>, ErrorKind> { Ok(Box::new(Twice)) };
    e.set_decoders(Decoders::none().with(Coding::Gzip, twice));
    let seen = Seen::default();
    let header = PausesAtTheEnd::default();
    let o = e.options_mut();
    o.set_url(Some(format!("http://127.0.0.1:{PORT}/").as_bytes()))
        .unwrap();
    o.output.verbose = true;
    o.http.accept_encoding = Some(crate::coding::AcceptEncoding::All);
    o.callbacks.write = Some(Handler::write(seen.clone()).unwrap());
    o.callbacks.header = Some(Handler::header(header.clone()).unwrap());
    o.callbacks.debug = Some(Handler::debug(seen.clone()).unwrap());
    let id = m.add(Box::new(e), (), &mut NoEvents).unwrap();
    let mut unpaused = false;
    let mut passes = 0;
    let result = loop {
        passes += 1;
        assert!(passes < 100, "the transfer does not end");
        m.perform(&mut NoEvents).unwrap();
        if let Some(done) = m.info_read() {
            break done.result;
        }
        if !unpaused && *header.0.lock().unwrap() == 1 {
            unpaused = true;
            seen.0
                .lock()
                .unwrap()
                .push(("text", b"== unpause the head".to_vec()));
            m.pause(id, PauseRequest::CONT, &mut NoEvents).unwrap();
        }
    };
    assert_eq!(result, Ok(()));
    assert_eq!(seen.body(), b"aabbcc");
    let lines: Vec<String> = seen
        .text()
        .into_iter()
        .map(|l| l.trim_end().to_owned())
        .filter(|l| l.contains("[OUT]") || l.contains("[PAUSE]") || l.starts_with("=="))
        .skip_while(|l| !l.contains("PAUSE requested"))
        .collect();
    assert_eq!(
        lines,
        expect(
            "[WRITE] [OUT] PAUSE requested by client
            [WRITE] [OUT] paused, buffering 2 more bytes (0/67108864)
            [WRITE] [PAUSE] buffer 3 more bytes of type 1, total=3 -> 0
            == unpause the head
            [WRITE] [OUT] wrote 2 header bytes, type=3 -> 2
            [WRITE] [OUT] wrote 6 body bytes, type=1 -> 6
            [WRITE] [PAUSE] flushed 3/3 bytes, type=1 -> 0
            [WRITE] [OUT] done"
        )
    );
}

/// The write lines of a run, as `written` gathers them.
fn write_lines(ran: &Ran) -> Vec<String> {
    ran.seen
        .text()
        .into_iter()
        .filter(|l| l.starts_with("[WRITE] "))
        .map(|l| l.trim_end().to_owned())
        .collect()
}

/// Each kind of output is typed as C's writers mark it (`CLIENTWRITE_*`,
/// in hex): an interim response's head, a proxy's answer to `CONNECT`,
/// and the end of a body that ends with its connection. The C build
/// traces the same types for the same responses.
#[test]
fn each_kind_of_output_is_typed_as_c_marks_it() {
    let interim = b"HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nabc";
    let (ran, lines) = written(writing(), interim, |_| {});
    assert_eq!(ran.result, Ok(()));
    for want in [
        "[WRITE] download_write header(type=2c, blen=23) -> 0",
        "[WRITE] download_write header(type=24, blen=2) -> 0",
    ] {
        assert!(lines.iter().any(|l| l == want), "{want}: {lines:?}");
    }
    let (mut m, talk, _) = server(&[b"HTTP/1.0 200 OK\r\n\r\nabc"], true);
    let ran = get_with(&mut m, writing(), "/", talk, |_| {});
    assert_eq!(ran.result, Ok(()));
    let lines = write_lines(&ran);
    for want in [
        "[WRITE] download_write body(type=81, blen=0) -> 0",
        "[WRITE] client_write(type=81, len=0) -> 0",
    ] {
        assert!(lines.iter().any(|l| l == want), "{want}: {lines:?}");
    }
    let refused = b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n";
    let (mut m, talk, _) = server(&[refused], false);
    let ran = get_with(&mut m, writing(), "/", talk, tunneled);
    assert_eq!(ran.result, Err(ErrorKind::CouldntConnect));
    let lines = write_lines(&ran);
    for want in [
        "[WRITE] download_write header(type=1c, blen=24) -> 0",
        "[WRITE] download_write header(type=14, blen=19) -> 0",
        "[WRITE] download_write header(type=14, blen=2) -> 0",
    ] {
        assert!(lines.iter().any(|l| l == want), "{want}: {lines:?}");
    }
}

/// A body past the largest file allowed is not written: what the limit
/// leaves room for is, and the rest fails the transfer without a write.
#[test]
fn a_body_past_the_size_limit_is_not_written() {
    let reply = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n\
        5\r\nhello\r\n7\r\n world\n\r\n0\r\n\r\n";
    let (ran, lines) = written(writing(), reply, |o| {
        o.limits.max_filesize = NonZeroU64::new(5);
    });
    assert_eq!(ran.result, Err(ErrorKind::FilesizeExceeded));
    let bodies: Vec<_> = lines
        .iter()
        .filter(|l| l.starts_with("[WRITE] download_write body"))
        .collect();
    assert_eq!(bodies, ["[WRITE] download_write body(type=1, blen=5) -> 0"]);
}

/// Accepts the first write, pauses at the second, then accepts again.
#[derive(Clone, Default)]
struct PausesSecond(Arc<Mutex<u32>>);

impl WriteHandler for PausesSecond {
    fn write(&self, _: &mut TransferCx<'_>, _: &[u8]) -> Write {
        let mut calls = self.0.lock().unwrap();
        *calls += 1;
        if *calls == 2 {
            Write::Pause
        } else {
            Write::Accepted
        }
    }
}

/// A body written in pieces and paused after the first holds what the
/// handler did not take (`cw_out_do_write`).
#[test]
fn a_body_paused_part_way_holds_what_is_left() {
    const SIZE: usize = 40_000;
    let reply = [
        format!("HTTP/1.1 200 OK\r\nContent-Length: {SIZE}\r\n\r\n").into_bytes(),
        vec![b'a'; SIZE],
    ]
    .concat();
    let (mut m, _talk, _clock) = server(&[&reply], false);
    let mut e = writing();
    let seen = Seen::default();
    let writer = PausesSecond::default();
    let o = e.options_mut();
    o.set_url(Some(format!("http://127.0.0.1:{PORT}/").as_bytes()))
        .unwrap();
    o.output.verbose = true;
    o.limits.buffer_size = crate::options::BufferSize::clamped(65536);
    o.callbacks.write = Some(Handler::write(writer.clone()).unwrap());
    o.callbacks.debug = Some(Handler::debug(seen.clone()).unwrap());
    let id = m.add(Box::new(e), (), &mut NoEvents).unwrap();
    let mut passes = 0;
    let result = loop {
        passes += 1;
        assert!(passes < 100, "the transfer does not end");
        m.perform(&mut NoEvents).unwrap();
        if let Some(done) = m.info_read() {
            break done.result;
        }
        m.pause(id, PauseRequest::CONT, &mut NoEvents).unwrap();
    };
    assert_eq!(result, Ok(()));
    let left = SIZE - 16384;
    let want = format!("[WRITE] [OUT] paused, buffering {left} more bytes (0/67108864)");
    let lines: Vec<String> = seen
        .text()
        .into_iter()
        .map(|l| l.trim_end().to_owned())
        .collect();
    assert!(lines.contains(&want), "{lines:?}");
}
