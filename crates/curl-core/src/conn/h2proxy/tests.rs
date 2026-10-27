use super::*;

/// The proxy's answer is held to C's limit exactly (`Curl_dynhds_add`
/// under `Curl_http_resp_make`): a mebibyte of names and values over all
/// its fields, and no limit on their count; a field that fills what is
/// left is kept, one byte more is not.
#[test]
fn a_proxy_s_answer_is_held_to_c_s_limit_at_its_edges() {
    let max = Answer::MAX_BYTES;
    let mut a = Answer::new(200);
    assert_eq!(a.add(b"a", &vec![b'x'; max / 2 - 1]), Ok(()));
    let left = max - max / 2;
    assert_eq!(a.add(b"b", &vec![b'x'; left]), Err(OutOfMemory));
    assert_eq!(a.add(b"b", &vec![b'x'; left - 1]), Ok(()));
    assert_eq!(a.add(b"c", b""), Err(OutOfMemory));

    // A name alone filling the room is kept; one longer than it is not.
    let mut a = Answer::new(200);
    assert_eq!(a.add(&vec![b'n'; max + 1], b""), Err(OutOfMemory));
    assert_eq!(a.add(&vec![b'n'; max], b""), Ok(()));

    let mut a = Answer::new(200);
    for _ in 0..10_000 {
        assert_eq!(a.add(b"a", b"b"), Ok(()));
    }
}

/// The tunnel's stream closed with an error is one the proxy reset, as
/// C's `proxy_h2_on_stream_close` takes it, even with no RST_STREAM
/// before, as when a GOAWAY refuses it; closed with none, it is not.
#[test]
fn a_tunnel_closed_with_an_error_was_reset() {
    for (error, reset) in [(H2Error::REFUSED_STREAM, true), (H2Error::NO_ERROR, false)] {
        let mut t = Tunnel::new();
        t.stream = Some(StreamId(1));
        let closed = Event::Closed {
            stream: StreamId(1),
            error,
        };
        assert_eq!(t.heard(&closed), Ok(Heard::Fine));
        assert_eq!((t.closed, t.error, t.reset), (true, error, reset));
    }
}

/// The tunnel's DATA as a proxy sends it: `len` bytes counting on from
/// `from`, so bytes out of place show.
fn counting(from: usize, len: usize) -> Vec<u8> {
    (from..from + len).map(|i| (i % 251) as u8).collect()
}

/// What the tunnel holds is stored in about as much again, however long
/// the download: a read that leaves some of a DATA held while the next
/// comes lets go of what it read, as C's buffer frees each chunk read
/// (`recvbuf`). Each DATA here comes with half the one before still held,
/// so what is held never runs dry for the buffer to start over at.
#[test]
fn what_the_tunnel_read_is_let_go_of_while_more_comes() {
    const DATA: usize = 16 * 1024;
    let mut t = Tunnel::new();
    t.stream = Some(StreamId(1));
    let (mut came, mut taken) = (0, 0);
    let mut buf = vec![0; DATA];
    for round in 0..100 {
        let bytes = counting(came, DATA);
        came += DATA;
        let data = Event::Data {
            stream: StreamId(1),
            bytes: &bytes,
        };
        assert_eq!(t.heard(&data), Ok(Heard::Fine));
        let want = if round == 0 { DATA / 2 } else { DATA };
        assert_eq!(t.take(&mut buf[..want]), want);
        assert_eq!(buf[..want], counting(taken, want), "round {round}");
        taken += want;
        assert_eq!(t.held().len(), DATA / 2);
        let held_most = DATA + DATA / 2;
        assert!(
            t.stored() <= 4 * (held_most + DATA),
            "round {round}: {} stored for {} held",
            t.stored(),
            t.held().len()
        );
    }
}
