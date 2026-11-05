//! A WebSocket's transfer in callback mode: the 101, then the frames the
//! server sends decoded for the write handler, a ping answered.

use super::*;
use crate::ws::Meta;

/// The 101 test 2301's server sends, with nothing after it.
const SWITCH: &[u8] = b"HTTP/1.1 101 Switching to WebSockets\r\n\
Upgrade: websocket\r\nConnection: Upgrade\r\n\r\n";

/// A verbose transfer of `ws://` from a server replying `frames` after
/// the 101, closing after them, with the options `set` makes.
fn ws(frames: &[u8], set: impl FnOnce(&mut Options)) -> Ran {
    let mut reply = SWITCH.to_vec();
    reply.extend_from_slice(frames);
    run("/", &reply, true, |o| {
        let url = format!("ws://127.0.0.1:{PORT}/");
        o.set_url(Some(url.as_bytes())).unwrap();
        set(o);
    })
}

/// What the client sent after its request's head: its frames.
fn frames_sent(ran: &Ran) -> &[u8] {
    let end = fixture::find(&ran.request, b"\r\n\r\n").expect("a request head") + 4;
    &ran.request[end..]
}

/// A ping in the frames delivered is answered by a masked pong of its
/// payload, the text frame after it given to the write handler.
#[test]
fn a_ping_delivered_is_answered_with_a_pong() {
    let ran = ws(b"\x89\x02hi\x81\x01x", |_| {});
    assert_eq!(ran.result, Ok(()));
    let sent = frames_sent(&ran);
    assert_eq!(sent.len(), 8, "{sent:x?}");
    assert_eq!(&sent[..2], [0x8a, 0x82]);
    let mask = &sent[2..6];
    // Drawn from the system's random bytes: all four zero once in 2^32.
    assert_ne!(mask, [0; 4], "the mask is drawn");
    let payload: Vec<u8> = sent[6..].iter().zip(mask).map(|(b, m)| b ^ m).collect();
    assert_eq!(payload, b"hi");
    assert_eq!(ran.seen.body(), b"x");
    // The pong counts as sent, as C's `Curl_xfer_send` counts it.
    let size = ran.easy.report().sizes().request();
    assert_eq!(size, ran.request.len() as u64);
}

/// With CURLWS_NOAUTOPONG, and in raw mode, nothing answers the ping.
#[test]
fn a_ping_goes_unanswered_when_asked() {
    let ran = ws(b"\x89\x02hi\x81\x01x", |o| o.ws.no_auto_pong = true);
    assert_eq!(ran.result, Ok(()));
    assert_eq!(frames_sent(&ran), b"");
    let ran = ws(b"\x89\x02hi\x81\x01x", |o| o.ws.raw = true);
    assert_eq!(ran.result, Ok(()));
    assert_eq!(frames_sent(&ran), b"");
    assert_eq!(ran.seen.body(), b"\x89\x02hi\x81\x01x", "raw, as it came");
}

/// A frame the connection's end cuts short fails the transfer as C's
/// does, once the frames before it were delivered.
#[test]
fn a_frame_cut_short_by_the_end_fails() {
    let ran = ws(b"\x81\x01x\x81\x05ab", |_| {});
    assert_eq!(ran.result, Err(ErrorKind::RecvError));
    assert_eq!(ran.seen.body(), b"xab");
    let failure = ran.easy.report().failure().map(<[u8]>::to_vec);
    assert_eq!(
        failure.as_deref(),
        Some(&b"[WS] decode ended with incomplete frame"[..])
    );
}

/// A server that answers the request's head with the 101, and the
/// upload's `sends`th send after it with a close, then closes.
fn upload_server(sends: usize) -> (Multi, Conversation) {
    let clock = ManualClock::new().unwrap();
    let at = SocketAddr::from(([127, 0, 0, 1], PORT));
    let mut replies: Vec<&[u8]> = vec![SWITCH];
    replies.extend(std::iter::repeat_n(&b""[..], sends - 1));
    replies.push(b"\x88\x00");
    let talk = Conversation::replies(&replies, true).per_send();
    let net = FakeNet::new(clock.clone())
        .with_peer(at, Peer::Accepts)
        .with_conversation(at, talk.clone());
    let env = Env {
        clock: Box::new(clock),
        net: Box::new(net),
        arena: ArenaPolicy::new(16, 0).unwrap(),
        waker: None,
    };
    (Multi::new(env).unwrap(), talk)
}

/// The frame `sent` holds first: its first byte and its payload,
/// unmasked.
fn unmasked(sent: &[u8]) -> (u8, Vec<u8>) {
    assert_eq!(sent[1] & 0x80, 0x80, "masked");
    let len = usize::from(sent[1] & 0x7f);
    let mask = &sent[2..6];
    let payload = sent[6..6 + len]
        .iter()
        .zip(mask.iter().cycle())
        .map(|(b, m)| b ^ m)
        .collect();
    (sent[0], payload)
}

/// An upload after the 101 goes as a binary frame of what was read.
#[test]
fn an_upload_goes_as_binary_frames() {
    let (mut m, talk) = upload_server(1);
    let ran = get(&mut m, "/", talk, |o| {
        let url = format!("ws://127.0.0.1:{PORT}/");
        o.set_url(Some(url.as_bytes())).unwrap();
        o.method = Method::Upload;
        o.upload = Stream::new(b"abc").source(false);
    });
    assert_eq!(ran.result, Ok(()), "{:#?}", ran.seen.text());
    assert_eq!(unmasked(frames_sent(&ran)), (0x82, b"abc".to_vec()));
}

/// A read handler that starts a text frame of what it reads, the
/// frame's whole length named first (`curl_ws_start_frame`), keeping
/// what `curl_ws_meta` said as it first read.
struct Framing(crate::test_cell::Cell<bool>, MetaSaid);

/// What `curl_ws_meta` said to a handler.
type MetaSaid = Arc<std::sync::Mutex<Option<Option<crate::ws::Meta>>>>;

impl crate::handler::ReadHandler for Framing {
    fn read(&self, cx: &mut TransferCx<'_>, buf: &mut [u8]) -> crate::handler::Read {
        if self.0.get() {
            return crate::handler::Read::Eof;
        }
        self.0.set(true);
        *self.1.lock().unwrap() = Some(cx.ws_meta());
        let text = crate::ws::SendFlags {
            kind: Some(crate::ws::FrameKind::Text),
            more: false,
        };
        cx.ws_start_frame(text, 5).unwrap();
        buf[..5].copy_from_slice(b"hello");
        crate::handler::Read::Data(std::num::NonZeroUsize::new(5).unwrap())
    }
}

/// A frame the read handler starts takes what it reads as its payload,
/// sent as the frame it named rather than as binary. Before any frame
/// came, the handler is told of none, as C tells it of its frame made
/// zeroed.
#[test]
fn a_read_handler_starts_its_own_frame() {
    let said = MetaSaid::default();
    let (mut m, talk) = upload_server(1);
    let ran = get(&mut m, "/", talk, |o| {
        let url = format!("ws://127.0.0.1:{PORT}/");
        o.set_url(Some(url.as_bytes())).unwrap();
        o.method = Method::Upload;
        o.upload = UploadSource::Read {
            handler: Handler::read(Framing(crate::test_cell::Cell::new(false), said.clone()))
                .unwrap(),
            rewind: None,
            size: None,
        };
    });
    assert_eq!(ran.result, Ok(()), "{:#?}", ran.seen.text());
    assert_eq!(unmasked(frames_sent(&ran)), (0x81, b"hello".to_vec()));
    assert_eq!(*said.lock().unwrap(), Some(Some(Meta::Nothing)));
}

/// A write and what `curl_ws_meta` said of it.
type MetaWrite = (Vec<u8>, Option<crate::ws::Meta>);

/// Each write it is given with what `curl_ws_meta` says of it, after
/// pausing at the first.
#[derive(Clone, Default)]
struct MetaWrites {
    got: Arc<std::sync::Mutex<Vec<MetaWrite>>>,
    paused: Arc<crate::test_cell::Cell<bool>>,
}

impl crate::handler::WriteHandler for MetaWrites {
    fn write(&self, cx: &mut TransferCx<'_>, body: &[u8]) -> crate::handler::Write {
        if !self.paused.replace(true) {
            return crate::handler::Write::Pause;
        }
        self.got.lock().unwrap().push((body.to_vec(), cx.ws_meta()));
        crate::handler::Write::Accepted
    }
}

/// Frames held while the write handler paused are delivered once it
/// unpauses, each piece with its frame, an empty frame as a write of
/// nothing.
#[test]
fn frames_held_by_a_pause_are_delivered_with_their_meta() {
    use crate::ws::{Frame, FrameKind, FrameType};
    let mut reply = SWITCH.to_vec();
    reply.extend_from_slice(b"\x81\x02ab\x81\x00\x82\x02cd");
    let (mut m, _talk, _) = server(&[&reply], true);
    let mut e = Easy::new();
    let handler = MetaWrites::default();
    let o = e.options_mut();
    o.set_url(Some(format!("ws://127.0.0.1:{PORT}/").as_bytes()))
        .unwrap();
    o.limits.total = crate::time::TimeLimit::from_millis(10_000);
    o.callbacks.write = Some(Handler::write(handler.clone()).unwrap());
    let id = m.add(Box::new(e), (), &mut NoEvents).unwrap();
    for _ in 0..10 {
        m.perform(&mut NoEvents).unwrap();
    }
    assert!(m.info_read().is_none(), "over with its frames held");
    let mut result = None;
    for _ in 0..100 {
        m.pause(id, PauseRequest::CONT, &mut NoEvents).unwrap();
        m.perform(&mut NoEvents).unwrap();
        if let Some(msg) = m.info_read() {
            result = Some(msg.result);
            break;
        }
    }
    assert_eq!(result, Some(Ok(())));
    let frame = |kind, len| Frame {
        kind: FrameType { kind, more: false },
        offset: 0,
        bytes_left: 0,
        len,
    };
    assert_eq!(
        *handler.got.lock().unwrap(),
        [
            (b"ab".to_vec(), Some(Meta::Frame(frame(FrameKind::Text, 2)))),
            (Vec::new(), Some(Meta::Frame(frame(FrameKind::Text, 0)))),
            (
                b"cd".to_vec(),
                Some(Meta::Frame(frame(FrameKind::Binary, 2)))
            ),
        ]
    );
}

/// Without a TLS library wss:// is a scheme the build leaves out, as it
/// is for C built without one; ws:// is not.
#[test]
fn wss_needs_a_tls_library() {
    assert!(Easy::new().libraries().tls.is_none());
    let ran = run("/", SWITCH, true, |o| {
        let url = format!("wss://127.0.0.1:{PORT}/");
        o.set_url(Some(url.as_bytes())).unwrap();
    });
    assert_eq!(ran.result, Err(ErrorKind::UnsupportedProtocol));
    assert_eq!(ran.request, b"");
    // A 101 and the end of the connection: an empty reply (test 2300).
    assert_eq!(ws(b"", |_| {}).result, Err(ErrorKind::GotNothing));
}

/// In callback mode the WebSocket traces as it does connect-only, in
/// C's words: the switch, the frames decoded and passed to the writer,
/// the pong answering a ping and its flush.
#[test]
fn callback_mode_traces_its_frames_as_c_does() {
    let mut e = Easy::new();
    let components = crate::components::Components::new().unwrap();
    components.configure(b"ws");
    e.set_components(Some(components));
    let mut reply = SWITCH.to_vec();
    reply.extend_from_slice(b"\x89\x02hi\x81\x01x");
    let (mut m, talk, _) = server(&[&reply], true);
    let ran = get_with(&mut m, e, "/", talk, |o| {
        let url = format!("ws://127.0.0.1:{PORT}/");
        o.set_url(Some(url.as_bytes())).unwrap();
    });
    assert_eq!(ran.result, Ok(()));
    let ws: Vec<String> = ran
        .seen
        .text()
        .into_iter()
        .filter(|l| l.starts_with("[WS] "))
        .map(|l| l.trim_end().to_owned())
        .collect();
    // The bytes after the 101 are written before the switch is said
    // done, as C's `Curl_ws_accept` writes them.
    assert_eq!(
        ws,
        [
            "[WS] WS, using chunk size 65535",
            "[WS] Received 101, switch to WebSocket",
            "[WS] decoded head [PING payload=0/2]",
            "[WS] auto PONG to [PING payload=0/2]",
            "[WS] passed 2 bytes payload, 0 remain",
            "[WS] decoded passing [PING payload=2/2]",
            "[WS] decoded head [TEXT payload=0/1]",
            "[WS] passed 1 bytes payload, 0 remain",
            "[WS] decoded passing [TEXT payload=1/1]",
            "[WS] WS-ENC: sending [PONG payload=0/2]",
            "[WS] WS-ENC: buffered [PONG payload=2/2]",
            "[WS] flushed 8 bytes",
            "[WS] websocket established, callback mode",
        ]
    );
}

/// A read handler that plays its script: each call starts the frames it
/// names (`curl_ws_start_frame`) and then gives its bytes, or says the
/// end when it has none.
struct Scripted(std::sync::Mutex<Vec<(Option<u64>, &'static [u8])>>);

impl crate::handler::ReadHandler for Scripted {
    fn read(&self, cx: &mut TransferCx<'_>, buf: &mut [u8]) -> crate::handler::Read {
        let mut script = self.0.lock().unwrap();
        if script.is_empty() {
            return crate::handler::Read::Eof;
        }
        let (start, bytes) = script.remove(0);
        if let Some(len) = start {
            let text = crate::ws::SendFlags {
                kind: Some(crate::ws::FrameKind::Text),
                more: false,
            };
            cx.ws_start_frame(text, len).unwrap();
        }
        match std::num::NonZeroUsize::new(bytes.len()) {
            Some(n) => {
                buf[..bytes.len()].copy_from_slice(bytes);
                crate::handler::Read::Data(n)
            }
            None => crate::handler::Read::Eof,
        }
    }
}

/// A ws:// upload by `script`, its read component traced.
fn upload(script: Vec<(Option<u64>, &'static [u8])>) -> (Ran, Vec<String>) {
    let sends = script.len();
    let (mut m, talk) = upload_server(sends);
    let mut e = Easy::new();
    let components = crate::components::Components::new().unwrap();
    components.configure(b"read");
    e.set_components(Some(components));
    let ran = get_with(&mut m, e, "/", talk, |o| {
        let url = format!("ws://127.0.0.1:{PORT}/");
        o.set_url(Some(url.as_bytes())).unwrap();
        o.method = Method::Upload;
        o.upload = UploadSource::Read {
            handler: Handler::read(Scripted(std::sync::Mutex::new(script))).unwrap(),
            rewind: None,
            size: None,
        };
    });
    let reads = ran
        .seen
        .text()
        .into_iter()
        .filter(|l| l.starts_with("[READ] cr_ws_read("))
        .map(|l| l.trim_end().to_owned())
        .collect();
    (ran, reads)
}

/// A frame the handler starts takes its payload from the reads after,
/// each no longer than what the frame still owes, until it is whole.
#[test]
fn a_started_frame_takes_the_reads_after_it() {
    let (ran, reads) = upload(vec![(Some(10), b"hello"), (None, b"world")]);
    assert_eq!(ran.result, Ok(()), "{:#?}", ran.seen.text());
    assert_eq!(unmasked(frames_sent(&ran)), (0x81, b"helloworld".to_vec()));
    // Each read, with payload still to come, says no end.
    assert_eq!(reads.len(), 2, "{reads:#?}");
    assert!(reads.iter().all(|l| l.ends_with("eos=0")), "{reads:#?}");
    // The second read asks no more than the frame still owes.
    assert!(
        reads[1].starts_with("[READ] cr_ws_read(len=5) "),
        "{reads:#?}"
    );
}

/// A handler that starts a frame and says its end in the same call is
/// asked again: the end is the frame's payload's to come
/// (`Curl_creader_clear_eos`).
#[test]
fn a_frame_started_at_the_end_asks_for_its_payload() {
    let (ran, _) = upload(vec![(Some(5), b""), (None, b"hello")]);
    assert_eq!(ran.result, Ok(()), "{:#?}", ran.seen.text());
    assert_eq!(unmasked(frames_sent(&ran)), (0x81, b"hello".to_vec()));
}

/// A transfer of `ws://` whose server's bytes come `n` at a time, its
/// writes and their meta recorded, a first write paused if `pause`.
fn in_pieces(frames: &[u8], n: usize, pause: bool) -> (Ran, Vec<MetaWrite>) {
    let clock = ManualClock::new().unwrap();
    let at = SocketAddr::from(([127, 0, 0, 1], PORT));
    let mut reply = SWITCH.to_vec();
    reply.extend_from_slice(frames);
    let talk =
        Conversation::replies(&[&reply], true).giving(std::num::NonZeroUsize::new(n).unwrap());
    let net = FakeNet::new(clock.clone())
        .with_peer(at, Peer::Accepts)
        .with_conversation(at, talk.clone());
    let env = Env {
        clock: Box::new(clock),
        net: Box::new(net),
        arena: ArenaPolicy::new(16, 0).unwrap(),
        waker: None,
    };
    let mut m: Multi = Multi::new(env).unwrap();
    let handler = MetaWrites::default();
    handler.paused.set(!pause);
    let mut e = Easy::new();
    let o = e.options_mut();
    o.set_url(Some(format!("ws://127.0.0.1:{PORT}/").as_bytes()))
        .unwrap();
    o.limits.total = crate::time::TimeLimit::from_millis(10_000);
    o.callbacks.write = Some(Handler::write(handler.clone()).unwrap());
    let id = m.add(Box::new(e), (), &mut NoEvents).unwrap();
    let mut result = None;
    for _ in 0..10_000 {
        m.perform(&mut NoEvents).unwrap();
        if let Some(msg) = m.info_read() {
            result = Some(msg.result);
            break;
        }
        m.pause(id, PauseRequest::CONT, &mut NoEvents).unwrap();
    }
    let easy = m.remove(id, &mut NoEvents).unwrap().easy;
    let ran = Ran {
        result: result.expect("the transfer ends"),
        request: talk.received(),
        seen: Seen::default(),
        easy: *easy,
    };
    let got = handler.got.lock().unwrap().clone();
    (ran, got)
}

/// Each write's meta follows on from the last's within its frame: its
/// offset is what came before, what is left what is still to come.
fn follows_on(writes: &[MetaWrite], total: u64) {
    let mut at = 0;
    for (bytes, meta) in writes {
        let Some(Meta::Frame(meta)) = meta else {
            panic!("a frame's meta: {writes:?}");
        };
        assert_eq!(meta.offset, at, "{writes:?}");
        at += bytes.len() as u64;
        assert_eq!(meta.bytes_left, total - at, "{writes:?}");
    }
    assert_eq!(at, total);
}

/// A frame that comes a byte at a time is written as it comes, each
/// piece told where in the frame it is. A ping in pieces is written but
/// for its last, which a pong answers, of that piece alone, as C's.
#[test]
fn a_frame_in_pieces_is_written_as_it_comes() {
    use crate::ws::FrameKind;
    let (ran, writes) = in_pieces(b"\x81\x05hello\x89\x02hi", 1, false);
    assert_eq!(ran.result, Ok(()));
    let of = |kind| -> Vec<MetaWrite> {
        writes
            .iter()
            .filter(|(_, m)| matches!(m, Some(Meta::Frame(f)) if f.kind.kind == kind))
            .cloned()
            .collect()
    };
    let text = of(FrameKind::Text);
    assert_eq!(text.len(), 5, "{writes:?}");
    follows_on(&text, 5);
    let ping = of(FrameKind::Ping);
    assert_eq!(ping.len(), 1, "{writes:?}");
    assert_eq!(ping[0].0, b"h");
    let sent = frames_sent(&ran);
    assert_eq!(&sent[..2], [0x8a, 0x81], "{sent:x?}");
    assert_eq!(sent[6] ^ sent[2], b'i');
}

/// A frame longer than the stage holds, paused at its first piece,
/// goes on from there once unpaused, each piece's meta its own.
#[test]
fn a_long_frame_paused_goes_on_where_it_stopped() {
    let mut frame = b"\x82\x7f\0\0\0\0\0\x01\x11\x70".to_vec();
    frame.extend(std::iter::repeat_n(b'z', 70_000));
    let (ran, writes) = in_pieces(&frame, 16_384, true);
    assert_eq!(ran.result, Ok(()));
    assert!(writes.len() > 1, "{}", writes.len());
    follows_on(&writes, 70_000);
}

/// A write handler that answers the first frame with a message of three
/// fragments, the last two continued without a type, as C allows.
#[derive(Clone, Default)]
struct Fragments(Arc<crate::test_cell::Cell<bool>>);

impl crate::handler::WriteHandler for Fragments {
    fn write(&self, cx: &mut TransferCx<'_>, _: &[u8]) -> crate::handler::Write {
        use crate::ws::{FrameKind, FrameLen, SendFlags};
        if !self.0.replace(true) {
            let sends = [
                (b"a", Some(FrameKind::Text), true),
                (b"b", None, true),
                (b"c", None, false),
            ];
            for (bytes, kind, more) in sends {
                let flags = SendFlags { kind, more };
                cx.ws_send(bytes, FrameLen::These, flags).unwrap();
            }
        }
        crate::handler::Write::Accepted
    }
}

/// Fragments continued without a type go out as continuations, each
/// said as C says it: the one to come with an info line, the last with
/// the ws component's.
#[test]
fn fragments_without_a_type_continue_the_message() {
    let mut e = Easy::new();
    let components = crate::components::Components::new().unwrap();
    components.configure(b"ws");
    e.set_components(Some(components));
    let mut reply = SWITCH.to_vec();
    reply.extend_from_slice(b"\x81\x01x");
    let (mut m, talk, _) = server(&[&reply], true);
    let ran = get_with(&mut m, e, "/", talk, |o| {
        let url = format!("ws://127.0.0.1:{PORT}/");
        o.set_url(Some(url.as_bytes())).unwrap();
        o.callbacks.write = Some(Handler::write(Fragments::default()).unwrap());
    });
    assert_eq!(ran.result, Ok(()));
    let sent = frames_sent(&ran);
    let heads: Vec<u8> = sent.chunks(7).map(|f| f[0]).collect();
    assert_eq!(heads, [0x01, 0x00, 0x80], "{sent:x?}");
    let text = ran.seen.text();
    let said = |line: &str| text.iter().any(|l| l.trim_end() == line);
    assert!(
        said(
            "[WS] setting CURLWS_CONT flag without message type is supported for \
             compatibility but highly discouraged"
        ),
        "{text:#?}"
    );
    assert!(
        said("[WS] no flags given; interpreting as continuation fragment for compatibility"),
        "{text:#?}"
    );
}

/// The 101 that takes up the upgrade is news to the multi
/// (`http_on_101_upgrade`'s `conn_changed`), heard as the transfer's next
/// step starts: in DONE, as the C build says against a server sending
/// the 101, a frame and its close.
#[test]
fn the_switch_is_said_as_the_next_step_starts() {
    let mut reply = SWITCH.to_vec();
    reply.extend_from_slice(b"\x81\x01x");
    let (mut m, talk, _) = server(&[&reply], true);
    let mut e = Easy::new();
    let c = crate::components::Components::new().unwrap();
    c.configure(b"multi");
    e.set_components(Some(c));
    let ran = get_with(&mut m, e, "/", talk, |o| {
        let url = format!("ws://127.0.0.1:{PORT}/");
        o.set_url(Some(url.as_bytes())).unwrap();
    });
    assert_eq!(ran.result, Ok(()));
    let states: Vec<String> = ran
        .seen
        .text()
        .into_iter()
        .map(|l| l.trim_end().to_owned())
        .filter(|l| l.starts_with("[MULTI] [") && (l.contains("] -> [") || l.contains("changed")))
        .collect();
    let done = states
        .iter()
        .position(|l| l == "[MULTI] [PERFORMING] -> [DONE]")
        .unwrap_or_else(|| panic!("{states:#?}"));
    assert_eq!(
        states[done..],
        [
            "[MULTI] [PERFORMING] -> [DONE]",
            "[MULTI] [DONE] multi changed, check CONNECT_PEND queue",
            "[MULTI] [DONE] -> [COMPLETED]",
            "[MULTI] [COMPLETED] -> [MSGSENT]",
        ],
        "{states:#?}"
    );
}
