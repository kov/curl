#![allow(clippy::disallowed_methods, clippy::disallowed_macros)]

use super::*;
use curl_core::http2::Session as _;

/// An event, owned.
#[derive(Debug, PartialEq, Eq)]
enum Seen {
    Header(i32, String, String),
    HeadersDone(i32, bool),
    Data(i32, Vec<u8>),
    DataEnd(i32),
    Closed(i32, u32),
    Settings,
    WindowUpdate,
    GoAway(i32, u32),
    Reset(i32, u32),
    PushField(i32, String, String),
    Promised(i32, i32),
    /// A frame read whole, as the trace describes it.
    Frame(String),
    /// A frame sent, as the trace describes it.
    Sent(String),
}

fn own(e: Event<'_>) -> Seen {
    let s = |b: &[u8]| String::from_utf8_lossy(b).into_owned();
    match e {
        Event::Header {
            stream,
            name,
            value,
        } => Seen::Header(stream.0, s(name), s(value)),
        Event::HeadersDone { stream, end_stream } => Seen::HeadersDone(stream.0, end_stream),
        Event::Data { stream, bytes } => Seen::Data(stream.0, bytes.to_vec()),
        Event::DataEnd { stream } => Seen::DataEnd(stream.0),
        Event::Closed { stream, error } => Seen::Closed(stream.0, error.0),
        Event::Settings { .. } => Seen::Settings,
        Event::WindowUpdate { .. } => Seen::WindowUpdate,
        Event::GoAway { last_stream, error } => Seen::GoAway(last_stream.0, error.0),
        Event::Reset { stream, error } => Seen::Reset(stream.0, error.0),
        Event::PushField {
            stream,
            name,
            value,
        } => Seen::PushField(stream.0, s(name), s(value)),
        Event::Promised { stream, promised } => Seen::Promised(stream.0, promised.0),
        Event::Received(f) => Seen::Frame(f.to_string()),
        Event::Sent(f) => Seen::Sent(f.to_string()),
    }
}

/// Move what `from` wants sent into `to`, reading bodies from `body`;
/// what `to` reads is kept in `seen`.
fn pump(from: &mut Session, to: &mut Session, body: &mut Vec<u8>, seen: &mut Vec<Seen>) {
    let mut wire = Vec::new();
    from.send(
        &mut |b| {
            wire.extend_from_slice(b);
            true
        },
        &mut |_, room| {
            let n = body.len().min(room.len());
            room[..n].copy_from_slice(&body[..n]);
            body.drain(..n);
            if body.is_empty() {
                BodyRead::Last(n)
            } else {
                BodyRead::Bytes(n)
            }
        },
        &mut |_| Heard::Fine,
    )
    .unwrap();
    let n = to
        .recv(&wire, &mut |e| {
            seen.push(own(e));
            Heard::Fine
        })
        .unwrap();
    assert_eq!(n, wire.len());
}

/// A request goes with its fields and body; the response comes back as
/// fields, data and the end of its stream, which then closes.
#[test]
fn a_request_and_its_response() {
    let mut client = Session::client().unwrap();
    let mut server = Session::server().unwrap();
    client
        .submit_settings(&[Setting::MaxConcurrentStreams(100)])
        .unwrap();
    server.submit_settings(&[]).unwrap();
    let fields: [(&[u8], &[u8]); 5] = [
        (b":method", b"POST"),
        (b":scheme", b"https"),
        (b":authority", b"example.com"),
        (b":path", b"/upload"),
        (b"user-agent", b"curl/test"),
    ];
    let stream = client.submit_request(&fields, true, 16).unwrap();
    assert_eq!(stream, StreamId(1));
    let mut body = b"hello".to_vec();
    let mut at_server = Vec::new();
    pump(&mut client, &mut server, &mut body, &mut at_server);
    assert!(at_server.contains(&Seen::Header(1, ":path".into(), "/upload".into())));
    assert!(at_server.contains(&Seen::Data(1, b"hello".to_vec())));
    assert!(at_server.contains(&Seen::DataEnd(1)));
    let response: [(&[u8], &[u8]); 2] = [(b":status", b"200"), (b"content-type", b"text/plain")];
    server
        .submit_response(StreamId(1), &response, true)
        .unwrap();
    let mut reply = b"ok\n".to_vec();
    let mut at_client = Vec::new();
    pump(&mut server, &mut client, &mut reply, &mut at_client);
    let stream_events: Vec<&Seen> = at_client
        .iter()
        .filter(|e| !matches!(e, Seen::Settings | Seen::WindowUpdate | Seen::Frame(_)))
        .collect();
    assert_eq!(
        stream_events,
        [
            &Seen::Header(1, ":status".into(), "200".into()),
            &Seen::Header(1, "content-type".into(), "text/plain".into()),
            &Seen::HeadersDone(1, false),
            &Seen::Data(1, b"ok\n".to_vec()),
            &Seen::DataEnd(1),
            &Seen::Closed(1, 0),
        ]
    );
    assert!(at_client.contains(&Seen::Settings));
    // The client consumes what it read, which opens its window.
    client.consume(StreamId(1), 3).unwrap();
    // The server set no limit: unlimited.
    assert_eq!(client.max_concurrent(), u32::MAX);
}

/// Each frame is told whole as it is sent and read, described as C's
/// trace describes it (`Curl_nghttp2_fr_print`): read, before what it
/// means; a DATA frame with its stream's window as it left it, a GOAWAY
/// with its debug data up to its zero byte.
#[test]
fn frames_are_told_as_c_describes_them() {
    let mut client = Session::client().unwrap();
    let mut server = Session::server().unwrap();
    client
        .submit_settings(&[
            Setting::MaxConcurrentStreams(100),
            Setting::InitialWindowSize(65536),
            Setting::EnablePush(false),
        ])
        .unwrap();
    server
        .submit_settings(&[Setting::MaxConcurrentStreams(9)])
        .unwrap();
    let fields: [(&[u8], &[u8]); 4] = [
        (b":method", b"GET"),
        (b":scheme", b"https"),
        (b":authority", b"x"),
        (b":path", b"/"),
    ];
    client.submit_request(&fields, false, 16).unwrap();
    let mut wire = Vec::new();
    let mut sent = Vec::new();
    client
        .send(
            &mut |b| {
                wire.extend_from_slice(b);
                true
            },
            &mut |_, _| BodyRead::Failed,
            &mut |e| {
                sent.push(own(e));
                Heard::Fine
            },
        )
        .unwrap();
    assert_eq!(sent.len(), 2, "{sent:?}");
    assert_eq!(sent[0], Seen::Sent("FRAME[SETTINGS, len=18]".into()));
    let Seen::Sent(headers) = &sent[1] else {
        panic!("{sent:?}")
    };
    assert!(headers.starts_with("FRAME[HEADERS, len="), "{headers}");
    assert!(headers.ends_with(", hend=1, eos=1]"), "{headers}");
    let mut at_server = Vec::new();
    server
        .recv(&wire, &mut |e| {
            at_server.push(own(e));
            Heard::Fine
        })
        .unwrap();
    let frames: Vec<&Seen> = at_server
        .iter()
        .filter(|e| matches!(e, Seen::Frame(_)))
        .collect();
    assert_eq!(frames[0], &Seen::Frame("FRAME[SETTINGS, len=18]".into()));
    // The fields of a HEADERS frame come before the frame is told whole.
    let at = |want: &Seen| at_server.iter().position(|e| e == want).unwrap();
    let path = at(&Seen::Header(1, ":path".into(), "/".into()));
    let whole = at_server
        .iter()
        .position(|e| matches!(e, Seen::Frame(f) if f.starts_with("FRAME[HEADERS")))
        .unwrap();
    assert!(path < whole, "{at_server:?}");
    let response: [(&[u8], &[u8]); 1] = [(b":status", b"200")];
    server
        .submit_response(StreamId(1), &response, true)
        .unwrap();
    let mut reply = b"ok\n".to_vec();
    let mut wire = Vec::new();
    let mut send = |server: &mut Session| {
        server
            .send(
                &mut |b| {
                    wire.extend_from_slice(b);
                    true
                },
                &mut |_, room| {
                    let n = reply.len();
                    room[..n].copy_from_slice(&reply);
                    reply.clear();
                    BodyRead::Last(n)
                },
                &mut |_| Heard::Fine,
            )
            .unwrap();
    };
    send(&mut server);
    // A GOAWAY goes ahead of what is queued: said after.
    server.goaway(H2Error::NO_ERROR, b"shutdown\0").unwrap();
    send(&mut server);
    let mut data_window = None;
    let mut settings = None;
    let mut at_client = Vec::new();
    client
        .recv(&wire, &mut |e| {
            match e {
                Event::Received(Frame {
                    kind: FrameKind::Data { window, .. },
                    ..
                }) => data_window = Some(window),
                Event::Settings {
                    max_concurrent,
                    enable_push,
                } => settings = Some((max_concurrent, enable_push)),
                _ => {}
            }
            at_client.push(own(e));
            Heard::Fine
        })
        .unwrap();
    let told: Vec<&Seen> = at_client
        .iter()
        .filter(|e| matches!(e, Seen::Frame(_) | Seen::Settings | Seen::DataEnd(_)))
        .collect();
    assert_eq!(
        told,
        [
            &Seen::Frame("FRAME[SETTINGS, len=6]".into()),
            &Seen::Settings,
            &Seen::Frame("FRAME[SETTINGS, ack=1]".into()),
            &Seen::Frame("FRAME[HEADERS, len=1, hend=1, eos=0]".into()),
            &Seen::Frame("FRAME[DATA, len=3, eos=1, padlen=0]".into()),
            &Seen::DataEnd(1),
            &Seen::Frame("FRAME[GOAWAY, error=0, reason='shutdown', last_stream=0]".into()),
        ],
        "{at_client:?}"
    );
    // What came is not given back yet; the window is as the client set it.
    assert_eq!(data_window, Some((3, 65536)));
    // The server's limit, and push it did not forbid.
    assert_eq!(settings, Some((9, true)));
}

/// A reset stream and a goaway are told, and the peer's settings read.
#[test]
fn resets_goaways_and_garbage() {
    let mut client = Session::client().unwrap();
    let mut server = Session::server().unwrap();
    client.submit_settings(&[]).unwrap();
    // A server's first frame is its SETTINGS.
    server
        .submit_settings(&[Setting::MaxConcurrentStreams(7)])
        .unwrap();
    let fields: [(&[u8], &[u8]); 4] = [
        (b":method", b"GET"),
        (b":scheme", b"https"),
        (b":authority", b"x"),
        (b":path", b"/"),
    ];
    client.submit_request(&fields, false, 16).unwrap();
    pump(&mut client, &mut server, &mut Vec::new(), &mut Vec::new());
    server.reset(StreamId(1), H2Error::CANCEL).unwrap();
    server.goaway(H2Error::NO_ERROR, b"").unwrap();
    let mut seen = Vec::new();
    pump(&mut server, &mut client, &mut Vec::new(), &mut seen);
    assert!(seen.contains(&Seen::Reset(1, 8)), "{seen:?}");
    assert!(seen.contains(&Seen::Closed(1, 8)), "{seen:?}");
    assert!(
        seen.iter().any(|e| matches!(e, Seen::GoAway(_, 0))),
        "{seen:?}"
    );
    assert_eq!(client.max_concurrent(), 7);
    assert_eq!(http2_error_text(8), "CANCEL");
    assert!(!version().is_empty());
}

/// A server's PUSH_PROMISE reaches a client that takes pushes as its
/// fields, on the stream it is beside, then the promise of its stream.
#[test]
fn a_push_promise_is_told_as_its_fields_then_the_promise() {
    let mut client = Session::client().unwrap();
    let mut server = Session::server().unwrap();
    client
        .submit_settings(&[Setting::EnablePush(true)])
        .unwrap();
    server.submit_settings(&[]).unwrap();
    let fields: [(&[u8], &[u8]); 4] = [
        (b":method", b"GET"),
        (b":scheme", b"https"),
        (b":authority", b"x"),
        (b":path", b"/"),
    ];
    client.submit_request(&fields, false, 16).unwrap();
    pump(&mut client, &mut server, &mut Vec::new(), &mut Vec::new());
    let promise: [(&[u8], &[u8]); 4] = [
        (b":method", b"GET"),
        (b":scheme", b"https"),
        (b":authority", b"x"),
        (b":path", b"/pushed"),
    ];
    let promised = server.submit_push_promise(StreamId(1), &promise).unwrap();
    assert_eq!(promised, StreamId(2));
    let mut seen = Vec::new();
    pump(&mut server, &mut client, &mut Vec::new(), &mut seen);
    let push: Vec<&Seen> = seen
        .iter()
        .filter(|e| matches!(e, Seen::PushField(..) | Seen::Promised(..)))
        .collect();
    assert_eq!(
        push,
        [
            &Seen::PushField(1, ":method".into(), "GET".into()),
            &Seen::PushField(1, ":scheme".into(), "https".into()),
            &Seen::PushField(1, ":authority".into(), "x".into()),
            &Seen::PushField(1, ":path".into(), "/pushed".into()),
            &Seen::Promised(1, 2),
        ]
    );
}

/// A stream's receive window is set as asked and read back; one grown is
/// told to the peer by the update submitted with it, the calls C makes.
#[test]
fn a_streams_window_is_set_and_grown() {
    let mut client = Session::client().unwrap();
    let mut server = Session::server().unwrap();
    client.submit_settings(&[]).unwrap();
    server.submit_settings(&[]).unwrap();
    let fields: [(&[u8], &[u8]); 4] = [
        (b":method", b"GET"),
        (b":scheme", b"https"),
        (b":authority", b"x"),
        (b":path", b"/"),
    ];
    let stream = client.submit_request(&fields, false, 16).unwrap();
    pump(&mut client, &mut server, &mut Vec::new(), &mut Vec::new());
    assert_eq!(client.stream_window(stream), 65535);
    client.set_stream_window(stream, 0).unwrap();
    assert_eq!(client.stream_window(stream), 0);
    client.set_stream_window(stream, 1 << 20).unwrap();
    // Nothing received to make up for, the update grows the window by as
    // much again, as nghttp2 documents it.
    client.submit_window_update(stream, 1 << 20).unwrap();
    assert_eq!(client.stream_window(stream), 2 << 20);
    let mut seen = Vec::new();
    pump(&mut client, &mut server, &mut Vec::new(), &mut seen);
    assert!(seen.contains(&Seen::WindowUpdate), "{seen:?}");
}

/// What is lent between calls reaches the callbacks through the pointer
/// the session was given, written through the owner after that pointer
/// was handed out, as each call lends anew; no session is made, so Miri
/// can check the borrows.
#[test]
fn what_is_lent_reaches_the_callbacks_through_the_user_pointer() {
    let mut lent = UserData::new().unwrap();
    let user = lent.user();
    let mut heard = Vec::new();
    for round in 0..2 {
        let mut events = |e: Event<'_>| {
            heard.push((round, own(e)));
            Heard::Fine
        };
        let events: *mut (dyn FnMut(Event<'_>) -> Heard + '_) = &mut events;
        // SAFETY: lent for the calls below only, taken back after.
        lent.get().events = Some(unsafe {
            core::mem::transmute::<*mut (dyn FnMut(Event<'_>) -> Heard + '_), *mut EventSink>(
                events,
            )
        });
        let mut body = |_: StreamId, room: &mut [u8]| {
            room[..2].copy_from_slice(b"ok");
            BodyRead::Last(2)
        };
        let body: *mut (dyn FnMut(StreamId, &mut [u8]) -> BodyRead + '_) = &mut body;
        // SAFETY: as above.
        lent.get().body = Some(unsafe {
            core::mem::transmute::<
                *mut (dyn FnMut(StreamId, &mut [u8]) -> BodyRead + '_),
                *mut BodySource,
            >(body)
        });
        let settings = Event::Settings {
            max_concurrent: 1,
            enable_push: false,
        };
        // SAFETY: the user pointer, its events lent.
        assert_eq!(unsafe { tell(user, settings) }, 0);
        let mut buf = [0u8; 8];
        let mut flags = 0u32;
        // SAFETY: the user pointer, its body lent; a buffer of its
        // length and flags to set. The session and source go unread.
        let n = unsafe {
            read_body(
                ptr::null_mut(),
                1,
                buf.as_mut_ptr(),
                buf.len(),
                &mut flags,
                ptr::null_mut(),
                user,
            )
        };
        assert_eq!((n, &buf[..2]), (2, &b"ok"[..]));
        assert_ne!(flags & sys::NGHTTP2_DATA_FLAG_EOF, 0);
        let taken = lent.get();
        taken.events = None;
        taken.body = None;
    }
    assert_eq!(heard, [(0, Seen::Settings), (1, Seen::Settings)]);
}

/// An HTTP/2 error code's text is nghttp2's for it, as C's messages say
/// it (`nghttp2_http2_strerror`).
#[test]
fn an_error_code_s_text_is_nghttp2_s() {
    assert_eq!(NGHTTP2.error_text(H2Error::CANCEL), "CANCEL");
    assert_eq!(
        NGHTTP2.error_text(H2Error::REFUSED_STREAM),
        "REFUSED_STREAM"
    );
    assert_eq!(NGHTTP2.error_text(H2Error(0xff)), "unknown");
}
