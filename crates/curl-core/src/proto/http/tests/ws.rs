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
