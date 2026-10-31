use std::fmt;

use proptest::prelude::*;

use super::frame::{Decoder, Encoder, Passed, Take, send_byte};
use super::queue::ChunkQueue;
use super::*;
use crate::untrusted;
use crate::ws::{FrameKind, FrameLen, FrameType, SendFlags};

/// What a WebSocket said and sent, and what its wire takes.
#[derive(Default)]
struct Rec {
    lines: Vec<String>,
    failed: Vec<String>,
    sent: Vec<u8>,
    /// How much the sends take in all before they would block: all if
    /// `None`.
    takes: Option<usize>,
    draws: u8,
    /// What the server sent and is not received yet; the connection's
    /// end once it is all received if `ends`.
    incoming: Vec<u8>,
    ends: bool,
}

impl Said for Rec {
    fn ws(&mut self, args: fmt::Arguments<'_>) {
        self.lines.push(format!("[WS] {args}"));
    }

    fn info(&mut self, args: fmt::Arguments<'_>) {
        self.lines.push(args.to_string());
    }

    fn fail(&mut self, kind: ErrorKind, args: fmt::Arguments<'_>) -> ErrorKind {
        self.failed.push(args.to_string());
        kind
    }
}

impl Wire for Rec {
    fn random(&mut self, out: &mut [u8]) -> Result<(), ErrorKind> {
        for b in out {
            self.draws = self.draws.wrapping_add(1);
            *b = self.draws;
        }
        Ok(())
    }

    fn send(&mut self, bytes: &[u8]) -> Result<usize, ErrorKind> {
        let n = self.takes.map_or(bytes.len(), |t| t.min(bytes.len()));
        if let Some(t) = self.takes.as_mut() {
            *t -= n;
        }
        self.sent.extend_from_slice(&bytes[..n]);
        Ok(n)
    }

    fn send_all(&mut self, bytes: &[u8]) -> Result<(), ErrorKind> {
        self.sent.extend_from_slice(bytes);
        Ok(())
    }

    fn recv(&mut self, buf: &mut [u8]) -> Result<Option<usize>, ErrorKind> {
        if self.incoming.is_empty() {
            return Ok(self.ends.then_some(0));
        }
        let n = self.incoming.len().min(buf.len());
        buf[..n].copy_from_slice(&self.incoming[..n]);
        self.incoming.drain(..n);
        Ok(Some(n))
    }
}

/// The frames a taker was handed, each its type and payload.
#[derive(Default)]
struct Frames {
    rec: Rec,
    got: Vec<(FrameType, Vec<u8>)>,
    /// How many bytes a take takes at most.
    most: Option<usize>,
}

impl Said for Frames {
    fn ws(&mut self, args: fmt::Arguments<'_>) {
        self.rec.ws(args);
    }

    fn info(&mut self, args: fmt::Arguments<'_>) {
        self.rec.info(args);
    }

    fn fail(&mut self, kind: ErrorKind, args: fmt::Arguments<'_>) -> ErrorKind {
        self.rec.fail(kind, args)
    }
}

impl Take for Frames {
    fn take(
        &mut self,
        bytes: &[u8],
        frame: FrameType,
        offset: u64,
        len: u64,
    ) -> Result<usize, Stop> {
        assert!(offset + bytes.len() as u64 <= len, "within the frame");
        let n = self.most.map_or(bytes.len(), |m| m.min(bytes.len()));
        if offset == 0 {
            self.got.push((frame, Vec::new()));
        }
        self.got
            .last_mut()
            .expect("a frame")
            .1
            .extend_from_slice(&bytes[..n]);
        Ok(n)
    }

    fn paused(&self) -> bool {
        false
    }
}

fn ft(kind: FrameKind, more: bool) -> FrameType {
    FrameType { kind, more }
}

/// The frames decoded, each its type and payload, and what was said of
/// the failure if one came.
type Decoded = (Vec<(FrameType, Vec<u8>)>, Option<Vec<String>>);

/// Decode `input` whole.
fn decode(input: &[u8]) -> Decoded {
    decode_pieces(&[input])
}

/// Decode `pieces`, each added to the buffer as it comes.
fn decode_pieces(pieces: &[&[u8]]) -> Decoded {
    let mut dec = Decoder::default();
    let mut q = ChunkQueue::new(CHUNK_SIZE, 1);
    let mut frames = Frames::default();
    for piece in pieces {
        q.write(piece).unwrap();
        loop {
            match dec.pass(&mut q, &mut frames) {
                Ok(Passed::Frame) => {}
                Ok(Passed::Again) => break,
                Err(Stop::Again) => break,
                Err(Stop::Failed(_)) => return (frames.got, Some(frames.rec.failed)),
            }
        }
    }
    (frames.got, None)
}

/// The frames of test 2700 come through as they were sent, a ping among
/// them, and a close with its code.
#[test]
fn each_kind_of_frame_is_read() {
    let input = b"\x81\x03txt\x82\x03bin\x89\x04ping\x8a\x04pong\x88\x07\x03\xe8close";
    let (got, failed) = decode(input);
    assert_eq!(failed, None);
    assert_eq!(
        got,
        [
            (ft(FrameKind::Text, false), b"txt".to_vec()),
            (ft(FrameKind::Binary, false), b"bin".to_vec()),
            (ft(FrameKind::Ping, false), b"ping".to_vec()),
            (ft(FrameKind::Pong, false), b"pong".to_vec()),
            (ft(FrameKind::Close, false), b"\x03\xe8close".to_vec()),
        ]
    );
}

/// A server's frame refused says what C says, then that decoding failed.
#[test]
fn a_refused_frame_says_why_as_c_does() {
    let cases: &[(&[u8], &str)] = &[
        (b"\x83\x00", "[WS] invalid opcode: 83"),
        (b"\x8b\x00", "[WS] invalid opcode: 8b"),
        (b"\xc1\x00", "[WS] invalid reserved bits: c1"),
        (b"\xa1\x00", "[WS] invalid reserved bits: a1"),
        (b"\x91\x00", "[WS] invalid reserved bits: 91"),
        (b"\x81\x83\x00\x00\x00\x00txt", "[WS] masked input frame"),
        (b"\x89\x7e\x00\x7e", "[WS] received PING frame is too big"),
        (b"\x8a\x7e\x00\x7e", "[WS] received PONG frame is too big"),
        (b"\x88\x7e\x00\x7e", "[WS] received CLOSE frame is too big"),
        (b"\x09\x00", "[WS] invalid fragmented PING frame"),
        (b"\x0a\x00", "[WS] invalid fragmented PONG frame"),
        (b"\x08\x00", "[WS] invalid fragmented CLOSE frame"),
        (b"\x80\x00", "[WS] no ongoing fragmented message to resume"),
        (b"\x00\x00", "[WS] no ongoing fragmented message to resume"),
        (
            b"\x01\x00\x81\x00",
            "[WS] fragmented message interrupted by new TEXT msg",
        ),
        (
            b"\x02\x00\x02\x00",
            "[WS] fragmented message interrupted by new BINARY msg",
        ),
        (
            b"\x82\x7f\x80\x00\x00\x00\x00\x00\x00\x00",
            "[WS] frame length longer than 63 bits not supported",
        ),
    ];
    for (input, why) in cases {
        let (_, failed) = decode(input);
        let failed = failed.unwrap_or_else(|| panic!("{input:x?} is refused"));
        assert_eq!(
            failed,
            [why.to_string(), "[WS] decode frame error 56".to_string()]
        );
    }
}

/// A ping or pong of 125 bytes is read, one of 126 refused.
#[test]
fn a_control_frame_is_at_most_125_bytes() {
    let mut ping = vec![0x89, 125];
    ping.extend([b'p'; 125]);
    let (got, failed) = decode(&ping);
    assert_eq!(failed, None);
    assert_eq!(got[0].1.len(), 125);
    let (_, failed) = decode(b"\x89\x7e");
    assert!(failed.is_some());
}

/// A length past 63 bits is refused again as it is asked again: the
/// decoder stays where it was.
#[test]
fn a_length_past_63_bits_is_refused_again() {
    let mut dec = Decoder::default();
    let mut q = ChunkQueue::new(CHUNK_SIZE, 1);
    q.write(b"\x82\x7f\xff\x00\x00\x00\x00\x00\x00\x01x")
        .unwrap();
    let mut frames = Frames::default();
    for _ in 0..2 {
        assert!(matches!(
            dec.pass(&mut q, &mut frames),
            Err(Stop::Failed(ErrorKind::RecvError))
        ));
    }
    assert_eq!(q.len(), 1);
}

/// Fragments of a message are read as one kind, more said of all but
/// the last; a control frame between them keeps the message open.
#[test]
fn fragments_carry_their_message_s_kind() {
    let input = b"\x01\x02ab\x8a\x00\x00\x01c\x80\x01d";
    let (got, failed) = decode(input);
    assert_eq!(failed, None);
    assert_eq!(
        got,
        [
            (ft(FrameKind::Text, true), b"ab".to_vec()),
            (ft(FrameKind::Pong, false), Vec::new()),
            (ft(FrameKind::Text, true), b"c".to_vec()),
            (ft(FrameKind::Text, false), b"d".to_vec()),
        ]
    );
}

/// The lengths of 16 and 64 bits are read.
#[test]
fn long_lengths_are_read() {
    let mut input = vec![0x82, 126, 0x01, 0x00];
    input.extend([7u8; 256]);
    input.extend([0x82, 127, 0, 0, 0, 0, 0, 1, 0, 0]);
    input.extend([9u8; 65536]);
    let (got, failed) = decode(&input);
    assert_eq!(failed, None);
    assert_eq!(got.len(), 2);
    assert_eq!(got[0].1, vec![7u8; 256]);
    assert_eq!(got[1].1.len(), 65536);
}

/// The first byte of a frame sent is C's for every flag the
/// application gives, a message under way or not.
#[test]
fn a_frame_sent_starts_as_c_starts_it() {
    use FrameKind::*;
    let flags = |kind, more| SendFlags { kind, more };
    let mut rec = Rec::default();
    let cases = [
        (flags(Some(Text), false), false, Ok(0x81)),
        (flags(Some(Text), false), true, Ok(0x80)),
        (flags(Some(Text), true), false, Ok(0x01)),
        (flags(Some(Text), true), true, Ok(0x00)),
        (flags(Some(Binary), false), false, Ok(0x82)),
        (flags(Some(Binary), true), false, Ok(0x02)),
        (flags(Some(Close), false), true, Ok(0x88)),
        (flags(Some(Ping), false), false, Ok(0x89)),
        (flags(Some(Pong), false), false, Ok(0x8a)),
        (flags(None, false), true, Ok(0x80)),
        (flags(None, true), true, Ok(0x00)),
        (
            flags(None, false),
            false,
            Err(ErrorKind::BadFunctionArgument),
        ),
        (
            flags(None, true),
            false,
            Err(ErrorKind::BadFunctionArgument),
        ),
        (
            flags(Some(Close), true),
            false,
            Err(ErrorKind::BadFunctionArgument),
        ),
        (
            flags(Some(Ping), true),
            false,
            Err(ErrorKind::BadFunctionArgument),
        ),
        (
            flags(Some(Pong), true),
            false,
            Err(ErrorKind::BadFunctionArgument),
        ),
    ];
    for (f, cont, want) in cases {
        assert_eq!(send_byte(&mut rec, f, cont), want, "{f:?} {cont}");
    }
    assert_eq!(
        rec.failed,
        [
            "[WS] no flags given",
            "[WS] No ongoing fragmented message to continue",
            "[WS] CLOSE frame must not be fragmented",
            "[WS] PING frame must not be fragmented",
            "[WS] PONG frame must not be fragmented",
        ]
    );
}

fn text() -> SendFlags {
    SendFlags {
        kind: Some(FrameKind::Text),
        more: false,
    }
}

/// A frame is masked by the four bytes drawn for it, its length in 7,
/// 16 or 64 bits as it needs.
#[test]
fn a_frame_is_masked_and_sized() {
    let mut rec = Rec::default();
    let mut enc = Encoder::default();
    let mut out = ChunkQueue::new(CHUNK_SIZE, 2);
    enc.add_frame(&mut rec, text(), 3, &mut out, false).unwrap();
    assert_eq!(enc.write_payload(&mut rec, b"abc", &mut out), Ok(3));
    let mut got = vec![0u8; out.len()];
    out.read(&mut got);
    assert_eq!(got, [0x81, 0x83, 1, 2, 3, 4, b'a' ^ 1, b'b' ^ 2, b'c' ^ 3]);
    for (len, head) in [(125u64, 2usize), (126, 4), (65535, 4), (65536, 10)] {
        let mut enc = Encoder::default();
        let mut out = ChunkQueue::new(CHUNK_SIZE, 2);
        enc.add_frame(&mut rec, text(), len, &mut out, true)
            .unwrap();
        assert_eq!(out.len(), head + 4, "{len}");
    }
}

/// A control frame longer than 125 bytes is not sent.
#[test]
fn a_long_control_frame_is_not_sent() {
    let mut rec = Rec::default();
    let mut enc = Encoder::default();
    let mut out = ChunkQueue::new(CHUNK_SIZE, 2);
    let ping = SendFlags {
        kind: Some(FrameKind::Ping),
        more: false,
    };
    assert_eq!(
        enc.add_frame(&mut rec, ping, 126, &mut out, false),
        Err(ErrorKind::TooLarge)
    );
    assert_eq!(rec.failed, ["[WS] given PING frame is too big"]);
}

/// A connection that takes a part of a frame's bytes has the
/// application told how much of its payload went; the rest goes as it
/// gives it again.
#[test]
fn a_short_send_says_what_of_the_payload_went() {
    let mut rec = Rec {
        takes: Some(8),
        ..Rec::default()
    };
    let mut ws = WsConn::new(&mut rec).unwrap();
    let payload = b"0123456789";
    // The head (6 bytes) and two bytes of payload go.
    let sent = ws.send(&mut rec, payload, FrameLen::These, text(), false);
    assert_eq!(sent, Ok(2));
    rec.takes = None;
    let sent = ws.send(&mut rec, &payload[2..], FrameLen::These, text(), false);
    assert_eq!(sent, Ok(8));
    assert_eq!(rec.sent.len(), 16);
}

/// A frame given its length up front takes its payload in the sends
/// after; one longer than what is left is refused.
#[test]
fn a_frame_s_payload_comes_after_its_length() {
    let mut rec = Rec::default();
    let mut ws = WsConn::new(&mut rec).unwrap();
    let binary = SendFlags {
        kind: Some(FrameKind::Binary),
        more: false,
    };
    assert_eq!(
        ws.send(&mut rec, b"", FrameLen::Total(4), binary, false),
        Ok(0)
    );
    assert_eq!(
        ws.send(&mut rec, b"ab", FrameLen::These, binary, false),
        Ok(2)
    );
    assert_eq!(
        ws.send(&mut rec, b"cde", FrameLen::These, binary, false),
        Err(Stop::Failed(ErrorKind::BadFunctionArgument))
    );
    assert_eq!(
        rec.failed,
        ["[WS] unaligned frame size (sending 3 instead of 2)"]
    );
    assert_eq!(
        ws.send(&mut rec, b"cd", FrameLen::These, binary, false),
        Ok(2)
    );
    assert_eq!(ws.start_frame(&mut rec, binary, 1), Ok(()));
    assert_eq!(
        ws.start_frame(&mut rec, binary, 1),
        Err(ErrorKind::SendError)
    );
}

/// A ping received is answered by a pong of its payload before the next
/// frame sent, and not handed on.
#[test]
fn a_ping_is_answered() {
    let mut rec = Rec::default();
    let mut ws = WsConn::new(&mut rec).unwrap();
    rec.incoming = b"\x89\x02hi\x81\x01x".to_vec();
    let mut buf = [0u8; 16];
    let frame = ws.recv(&mut rec, &mut buf, true).unwrap();
    assert_eq!(frame.kind, ft(FrameKind::Text, false));
    assert_eq!(&buf[..frame.len], b"x");
    assert!(ws.pending());
    ws.send_pending(&mut rec, false);
    assert!(!ws.pending());
    assert_eq!(rec.sent, [0x8a, 0x82, 1, 2, 3, 4, b'h' ^ 1, b'i' ^ 2]);
}

/// The end of the stream with nothing held is the connection closing.
#[test]
fn a_receive_at_the_end_got_nothing() {
    let mut rec = Rec::default();
    let mut ws = WsConn::new(&mut rec).unwrap();
    let got = ws.recv(&mut rec, &mut [0u8; 4], true);
    assert_eq!(got, Err(Stop::Again));
    rec.ends = true;
    let got = ws.recv(&mut rec, &mut [0u8; 4], true);
    assert_eq!(got, Err(Stop::Failed(ErrorKind::GotNothing)));
}

/// Frames that make sense, for the decoder's fuzzing.
const SAMPLES: &[&[u8]] = &[
    b"\x81\x03txt\x82\x03bin\x89\x04ping\x8a\x04pong\x88\x07\x03\xe8close",
    b"\x01\x02ab\x8a\x00\x00\x01c\x80\x01d",
    b"\x82\x7e\x00\x04abcd\x82\x7f\x00\x00\x00\x00\x00\x00\x00\x02ef",
    b"\x81\x00\x89\x00\x8a\x00\x88\x00",
];

/// The bytes frames are made of.
const WORDS: &[&[u8]] = &[
    b"\x81",
    b"\x82",
    b"\x01",
    b"\x02",
    b"\x00",
    b"\x80",
    b"\x88",
    b"\x89",
    b"\x8a",
    b"\x7e",
    b"\x7f",
    b"\x03",
    b"\x00\x00",
    b"abc",
];

proptest! {
    #![proptest_config(untrusted::config(512))]

    /// Whatever a server sends is frames, a refusal, or more waited
    /// for, never a panic; and it reads the same however the reads cut
    /// it.
    #[test]
    fn any_bytes_read_the_same_cut_anywhere(
        input in untrusted::input(WORDS, SAMPLES, 24),
        cuts in untrusted::cuts(),
    ) {
        let whole = decode(&input);
        let pieces = untrusted::pieces(&input, &cuts);
        prop_assert_eq!(decode_pieces(&pieces), whole);
    }

    /// A receive into a buffer of any size gets the same payloads, a
    /// taker that takes a byte at a time too.
    #[test]
    fn any_bytes_read_the_same_taken_a_byte_at_a_time(
        input in untrusted::input(WORDS, SAMPLES, 24),
    ) {
        let whole = decode(&input);
        let mut dec = Decoder::default();
        let mut q = ChunkQueue::new(CHUNK_SIZE, 1);
        let mut frames = Frames { most: Some(1), ..Frames::default() };
        q.write(&input).unwrap();
        let mut failed = None;
        for _ in 0..input.len() * 4 + 4 {
            match dec.pass(&mut q, &mut frames) {
                Ok(_) | Err(Stop::Again) => {}
                Err(Stop::Failed(_)) => {
                    failed = Some(std::mem::take(&mut frames.rec.failed));
                    break;
                }
            }
        }
        prop_assert_eq!((frames.got, failed), whole);
    }
}

/// Every split point of the samples reads the same as the whole.
#[test]
fn every_split_point_reads_the_same() {
    for sample in SAMPLES {
        let whole = decode(sample);
        for at in 0..=sample.len() {
            let (a, b) = sample.split_at(at);
            assert_eq!(decode_pieces(&[a, b]), whole, "{sample:x?} cut at {at}");
        }
    }
}

/// A pong waits while a frame's payload is under way, and goes with the
/// flush after its last byte, behind it.
#[test]
fn a_pong_waits_for_the_frame_under_way() {
    let mut rec = Rec::default();
    let mut ws = WsConn::new(&mut rec).unwrap();
    assert_eq!(
        ws.send(&mut rec, b"ab", FrameLen::Total(4), text(), false),
        Ok(2)
    );
    ws.add_pong(b"p");
    assert_eq!(ws.flush(&mut rec, false), Ok(()));
    assert!(ws.pending(), "no pong inside a frame");
    assert_eq!(rec.sent.len(), 8);
    assert_eq!(
        ws.send(&mut rec, b"cd", FrameLen::These, text(), false),
        Ok(2)
    );
    assert_eq!(ws.flush(&mut rec, false), Ok(()));
    assert!(!ws.pending());
    assert_eq!(rec.sent.len(), 10 + 7);
    assert_eq!(&rec.sent[10..12], [0x8a, 0x81]);
}

/// A flush with room in the send buffer adds the pong waiting, even with
/// nothing else to send.
#[test]
fn a_flush_sends_the_pong_waiting() {
    let mut rec = Rec::default();
    let mut ws = WsConn::new(&mut rec).unwrap();
    ws.add_pong(b"hi");
    assert_eq!(ws.flush(&mut rec, false), Ok(()));
    assert!(!ws.pending());
    assert_eq!(&rec.sent[..2], [0x8a, 0x82]);
    assert_eq!(rec.sent.len(), 8);
}

/// The debug test build's `CURL_WS_CHUNK_EAGAIN` sends at most that many
/// bytes at a flush, the rest waiting as if the connection blocked.
#[test]
fn a_debug_chunk_limit_cuts_each_flush() {
    let mut rec = Rec::default();
    let mut ws = WsConn::new(&mut rec).unwrap();
    ws.debugging.chunk_eagain = 4;
    ws.add_pong(b"hi");
    assert_eq!(ws.flush(&mut rec, false), Err(Stop::Again));
    assert_eq!(rec.sent.len(), 4);
    assert_eq!(ws.flush(&mut rec, false), Ok(()), "the last 4 fit");
    assert_eq!(rec.sent.len(), 8);
    ws.debugging.chunk_eagain = 8;
    ws.add_pong(b"hi");
    assert_eq!(
        ws.flush(&mut rec, false),
        Ok(()),
        "a flush that fits goes whole"
    );
    assert_eq!(rec.sent.len(), 16);
}

/// A frame's trace says NON-FINAL of a fragment, and nothing of the
/// last frame of a message, as C's does.
#[test]
fn a_fragment_is_traced_as_non_final() {
    let mut dec = Decoder::default();
    let mut q = ChunkQueue::new(CHUNK_SIZE, 1);
    let mut frames = Frames::default();
    q.write(b"\x01\x01a\x80\x01b").unwrap();
    while let Ok(Passed::Frame) = dec.pass(&mut q, &mut frames) {}
    let heads: Vec<&String> = frames
        .rec
        .lines
        .iter()
        .filter(|l| l.contains("decoded head"))
        .collect();
    assert_eq!(heads.len(), 2, "{:?}", frames.rec.lines);
    assert!(heads[0].contains("NON-FINAL"), "{heads:?}");
    assert!(!heads[1].contains("NON-FINAL"), "{heads:?}");
}
