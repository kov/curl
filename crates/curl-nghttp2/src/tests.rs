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
        Event::Closed { stream, error } => Seen::Closed(stream.0, error),
        Event::Settings => Seen::Settings,
        Event::WindowUpdate { .. } => Seen::WindowUpdate,
        Event::GoAway { last_stream, error } => Seen::GoAway(last_stream.0, error),
        Event::Reset { stream, error } => Seen::Reset(stream.0, error),
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
    let stream = client.submit_request(&fields, true).unwrap();
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
        .filter(|e| !matches!(e, Seen::Settings | Seen::WindowUpdate))
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
    client.submit_request(&fields, false).unwrap();
    pump(&mut client, &mut server, &mut Vec::new(), &mut Vec::new());
    server.reset(StreamId(1), 8).unwrap();
    server.goaway(0, b"").unwrap();
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
