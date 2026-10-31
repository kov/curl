//! RTSP's readings of a server's header lines, and its RTP filter, as C
//! reads the same bytes; and none of them panicking on any.

use super::*;
use crate::easy::RtspState;

/// What the filter gave out, each piece as it went.
#[derive(Debug, Default, PartialEq, Eq)]
struct Got {
    /// Body bytes, joined.
    body: Vec<u8>,
    /// Bytes past the body, which went nowhere.
    dropped: usize,
    packets: Vec<(u8, Vec<u8>)>,
}

/// The filter's output, with `due` body bytes still to come.
struct Sink {
    due: u64,
    got: Got,
    /// A packet write fails from this many on.
    fail_after: Option<usize>,
}

impl RtpOut for Sink {
    fn body_due(&self) -> bool {
        self.due > 0
    }

    fn junk(&mut self, bytes: &[u8]) -> Result<(), ErrorKind> {
        let n = usize::try_from(self.due).map_or(bytes.len(), |d| d.min(bytes.len()));
        self.got.body.extend_from_slice(&bytes[..n]);
        self.got.dropped += bytes.len() - n;
        self.due -= n as u64;
        Ok(())
    }

    fn packet(&mut self, channel: u8, message: &[u8]) -> Result<(), ErrorKind> {
        if self.fail_after.is_some_and(|n| self.got.packets.len() >= n) {
            return Err(ErrorKind::WriteError);
        }
        assert_eq!(message[0], b'$');
        assert_eq!(message[1], channel);
        let len = usize::from(u16::from_be_bytes([message[2], message[3]]));
        assert_eq!(message.len(), len + 4, "a whole message");
        self.got.packets.push((channel, message[4..].to_vec()));
        Ok(())
    }

    fn note(&mut self, _: fmt::Arguments<'_>) {}
}

fn channels(of: &[u8]) -> RtspState {
    let mut state = RtspState::default();
    for &c in of {
        state.add_channel(c);
    }
    state
}

/// `pieces` through one connection's filter in turn, `due` body bytes
/// expected: what came out, and how much of the input was left for a head.
fn filter(pieces: &[&[u8]], due: u64, on: &RtspState, receive: bool) -> (Got, usize) {
    let mut conn = RtspConn::default();
    let mut sink = Sink {
        due,
        got: Got::default(),
        fail_after: None,
    };
    let mut left = 0;
    for piece in pieces {
        let used = conn.filter(piece, receive, on, &mut sink).unwrap();
        assert!(used <= piece.len());
        if conn.in_header {
            left += piece.len() - used;
            break;
        }
        assert_eq!(used, piece.len(), "all taken outside a head");
    }
    (sink.got, left)
}

/// A body with messages inside it and after it, as test 571's server
/// sends them, comes out the same however the reads split it: the body
/// alone to the body, each message whole to the interleave handler.
#[test]
fn messages_are_taken_out_wherever_the_reads_split_them() {
    let input: &[u8] = b"$\x00\x00\x03abche$\x01\x00\x02XYllo$\x00\x00\x00$\x01\x00\x01Z";
    let on = channels(&[0, 1]);
    let want = Got {
        body: b"hello".to_vec(),
        dropped: 0,
        packets: vec![
            (0, b"abc".to_vec()),
            (1, b"XY".to_vec()),
            (0, vec![]),
            (1, b"Z".to_vec()),
        ],
    };
    assert_eq!(filter(&[input], 5, &on, false), (want, 0));
    for at in 0..=input.len() {
        let (a, b) = input.split_at(at);
        let (got, _) = filter(&[a, b], 5, &on, false);
        assert_eq!(got.packets.len(), 4, "split at {at}");
        assert_eq!(got.body, b"hello", "split at {at}");
    }
    let bytes: Vec<&[u8]> = input.chunks(1).collect();
    assert_eq!(filter(&bytes, 5, &on, false).0.body, b"hello");
}

/// A `$` on a channel no `Transport:` named is body, or junk past it
/// (`RTSP: invalid RTP channel`), split from the channel byte or not.
#[test]
fn a_message_on_another_channel_is_body() {
    let on = channels(&[1]);
    let input: &[u8] = b"$\x05\x00\x01Q$\x01\x00\x01R";
    let (got, left) = filter(&[input], 3, &on, false);
    assert_eq!(
        (got.body.as_slice(), got.packets.as_slice(), left),
        (&b"$\x05\x00"[..], &[(1, b"R".to_vec())][..], 0),
        "{got:?}"
    );
    let (got, _) = filter(&[b"$", b"\x05\x00\x01Q"], 3, &on, false);
    assert_eq!(got.body, b"$\x05\x00", "the `$` read before still goes");
}

/// Outside a body the next response's head stops the filter, its bytes
/// left for the head parser; a receive reads no head, and takes them.
#[test]
fn a_response_s_head_stops_the_filter() {
    let on = channels(&[0]);
    let input: &[u8] = b"$\x00\x00\x01Ajunk RTSP/1.0 200 OK\r\n";
    let (got, left) = filter(&[input], 0, &on, false);
    // What came before it goes nowhere, not even as junk.
    assert_eq!(got.packets, [(0, b"A".to_vec())]);
    assert_eq!((got.dropped, left), (0, 17));
    // Part of the prefix, at a read's end, stops it too.
    let (_, left) = filter(&[b"$\x00\x00\x01ARTS"], 0, &on, false);
    assert_eq!(left, 3);
    let (got, left) = filter(&[input], 0, &on, true);
    assert_eq!((got.dropped, left), (input.len() - 5, 0), "a receive");
    // Within a body it is body.
    let (got, left) = filter(&[b"RTSP/"], 5, &on, false);
    assert_eq!((got.body.as_slice(), left), (&b"RTSP/"[..], 0));
}

/// A message the handler fails is dropped whole: the filter starts over
/// at the next one.
#[test]
fn a_failed_write_drops_the_message() {
    let on = channels(&[0]);
    let mut conn = RtspConn::default();
    let mut sink = Sink {
        due: 0,
        got: Got::default(),
        fail_after: Some(0),
    };
    let input: &[u8] = b"$\x00\x00\x01A";
    assert_eq!(
        conn.filter(input, false, &on, &mut sink),
        Err(ErrorKind::WriteError)
    );
    assert_eq!((conn.state, conn.buf.len()), (Parse::Skip, 0));
    sink.fail_after = None;
    assert_eq!(conn.filter(input, false, &on, &mut sink), Ok(input.len()));
    assert_eq!(sink.got.packets, [(0, b"A".to_vec())]);
}

/// The CSeq is a number of at most `u32::MAX` past blanks; anything else
/// is none (`curlx_str_number`).
#[test]
fn a_cseq_is_read_as_c_reads_it() {
    for (value, want) in [
        (&b" 12\r\n"[..], Some(12)),
        (b"\t0", Some(0)),
        (b"4294967295", Some(u32::MAX)),
        (b"4294967296", None),
        (b"", None),
        (b" -1", None),
        (b" x1", None),
        (b"007", Some(7)),
    ] {
        assert_eq!(cseq(value), want, "{value:?}");
    }
}

/// A session id ends at a blank, a control byte, a byte above ASCII or
/// a `;`; a value with nothing, to its first zero byte, names none.
#[test]
fn a_session_id_is_read_as_c_reads_it() {
    for (value, want) in [
        (&b" abc;timeout=60\r\n"[..], Some(&b"abc"[..])),
        (b"abc\r\n", Some(b"abc")),
        (b" \r\n", Some(b"")),
        (b"a\x80b", Some(b"a")),
        (b"%41-b_c~\r\n", Some(b"%41-b_c~")),
        (b"", None),
        (b"  ", None),
        (b" \0abc", None),
    ] {
        assert_eq!(session_id(value).map(|(_, id)| id), want, "{value:?}");
    }
    assert_eq!(
        session_id(b" ab\0cd").map(|(said, _)| said),
        Some(&b"ab"[..]),
        "said to the zero byte"
    );
}

/// The first `interleaved=` names a channel or a range of them, each up
/// to 255; one that cannot be read is said, a range's start kept.
#[test]
fn interleaved_channels_are_read_as_c_reads_them() {
    let read = |value: &[u8]| {
        let mut state = RtspState::default();
        let said = parse_transport(value, &mut state);
        let on: Vec<u8> = (0..=255).filter(|&c| state.interleaves(c)).collect();
        (on, said.is_err())
    };
    assert_eq!(
        read(b" RTP/AVP/TCP;unicast;interleaved=5-7\r\n"),
        (vec![5, 6, 7], false)
    );
    assert_eq!(read(b"RTP/AVP/TCP;INTERLEAVED=3"), (vec![3], false));
    assert_eq!(read(b"interleaved=254-255"), (vec![254, 255], false));
    assert_eq!(read(b"interleaved=5-x"), (vec![5], true));
    assert_eq!(read(b"interleaved=256"), (vec![], true));
    assert_eq!(
        read(b"interleaved=x;interleaved=4"),
        (vec![], true),
        "the first only"
    );
    assert_eq!(read(b"interleaved=7-3"), (vec![], false), "an empty range");
    assert_eq!(read(b"unicast"), (vec![], false));
    assert_eq!(
        read(b"a;\0interleaved=1"),
        (vec![], false),
        "to the zero byte"
    );
}

/// The bytes a server's response may hold, around and inside messages.
const WORDS: &[&[u8]] = &[
    b"$",
    b"\x00",
    b"\x01",
    b"\x00\x02",
    b"\xff\xff",
    b"RTSP/",
    b"RTSP/1.0 200 OK\r\n",
    b"R",
    b"body",
    b"\r\n",
];

const STREAMS: &[&[u8]] = &[
    b"$\x00\x00\x03abche$\x01\x00\x02XYllo$\x00\x00\x00$\x01\x00\x01Z",
    b"$\x05\x00\x01Q$\x01\x00\x01RRTSP/1.0 200 OK\r\n",
];

const VALUES: &[&[u8]] = &[
    b" RTP/AVP/TCP;unicast;interleaved=0-1\r\n",
    b" 12\r\n",
    b" abc;timeout=60\r\n",
];

proptest::proptest! {
    #![proptest_config(crate::untrusted::config(256))]

    /// Any bytes, cut anywhere, on any channels, with any body due: the
    /// filter takes what it may and never panics; and, with no head to
    /// stop at, gives the same messages however the reads cut them.
    #[test]
    fn any_stream_is_filtered(
        input in crate::untrusted::input(WORDS, STREAMS, 24),
        cuts in crate::untrusted::cuts(),
        on in proptest::collection::vec(proptest::num::u8::ANY, 0..4),
        due in 0u64..64,
        receive in proptest::bool::ANY,
    ) {
        let on = channels(&on);
        let whole = filter(&[&input], due, &on, receive);
        let cut = filter(&crate::untrusted::pieces(&input, &cuts), due, &on, receive);
        if receive {
            proptest::prop_assert_eq!(whole.1, 0);
            proptest::prop_assert_eq!(&cut.0.packets, &whole.0.packets);
            proptest::prop_assert_eq!(&cut.0.body, &whole.0.body);
        }
    }

    /// Any header value is a CSeq, a session id and a transport, or none
    /// of them, and never a panic.
    #[test]
    fn any_value_is_read_or_refused(value in crate::untrusted::mutated(VALUES)) {
        let _cseq = cseq(&value);
        let _id = session_id(&value);
        let _said = parse_transport(&value, &mut RtspState::default());
    }
}
