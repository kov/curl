//! A WebSocket's transfer in callback mode: the 101, then the frames the
//! server sends decoded for the write handler, a ping answered.

use super::*;

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
    let payload: Vec<u8> = sent[6..].iter().zip(mask).map(|(b, m)| b ^ m).collect();
    assert_eq!(payload, b"hi");
    assert_eq!(ran.seen.body(), b"x");
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

/// A server that answers the request's head with the 101 and the next
/// thing sent, the upload's frame, with a close, then closes.
fn upload_server() -> (Multi, Conversation) {
    let clock = ManualClock::new().unwrap();
    let at = SocketAddr::from(([127, 0, 0, 1], PORT));
    let talk = Conversation::replies(&[SWITCH, b"\x88\x00"], true).per_send();
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
    let (mut m, talk) = upload_server();
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
/// frame's whole length named first (`curl_ws_start_frame`).
struct Framing(crate::test_cell::Cell<bool>);

impl crate::handler::ReadHandler for Framing {
    fn read(&self, cx: &mut TransferCx<'_>, buf: &mut [u8]) -> crate::handler::Read {
        if self.0.get() {
            return crate::handler::Read::Eof;
        }
        self.0.set(true);
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
/// sent as the frame it named rather than as binary.
#[test]
fn a_read_handler_starts_its_own_frame() {
    let (mut m, talk) = upload_server();
    let ran = get(&mut m, "/", talk, |o| {
        let url = format!("ws://127.0.0.1:{PORT}/");
        o.set_url(Some(url.as_bytes())).unwrap();
        o.method = Method::Upload;
        o.upload = UploadSource::Read {
            handler: Handler::read(Framing(crate::test_cell::Cell::new(false))).unwrap(),
            rewind: None,
            size: None,
        };
    });
    assert_eq!(ran.result, Ok(()), "{:#?}", ran.seen.text());
    assert_eq!(unmasked(frames_sent(&ran)), (0x81, b"hello".to_vec()));
}

/// A write and what `curl_ws_meta` said of it.
type MetaWrite = (Vec<u8>, Option<crate::ws::Frame>);

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
            (b"ab".to_vec(), Some(frame(FrameKind::Text, 2))),
            (Vec::new(), Some(frame(FrameKind::Text, 0))),
            (b"cd".to_vec(), Some(frame(FrameKind::Binary, 2))),
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
