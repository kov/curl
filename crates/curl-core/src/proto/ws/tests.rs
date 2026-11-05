use std::fmt;

use proptest::prelude::*;

use super::frame::{Decoder, Encoder, Passed, Take, send_byte};
use super::*;
use crate::bufq::ChunkQueue;
use crate::untrusted;
use crate::ws::{FrameKind, FrameLen, FrameType, SendFlags};

/// A send as the core takes one, the call said in the trace first.
fn api_send(
    ws: &mut WsConn,
    wire: &mut dyn Wire,
    raw: bool,
    bytes: &[u8],
    len: FrameLen,
    flags: SendFlags,
    in_callback: bool,
) -> Result<Sent, ErrorKind> {
    let asked = asked_of(len, flags);
    send_enters(bytes.len(), &asked, raw, |line| wire.ws(line));
    super::api_send(ws, wire, raw, bytes, &asked, in_callback)
}

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
    /// The most a receive gets at once: all there is if `None`.
    piece: Option<usize>,
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
        let n = self.piece.map_or(n, |p| p.min(n));
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
            b"\x01\x00\x82\x00",
            "[WS] fragmented message interrupted by new BINARY msg",
        ),
        (
            b"\x02\x00\x01\x00",
            "[WS] fragmented message interrupted by new TEXT msg",
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
    assert_eq!(
        ws.start_frame(&mut rec, AskedFrame::Frame(FrameLen::Total(1), binary)),
        Ok(())
    );
    assert_eq!(
        ws.start_frame(&mut rec, AskedFrame::Frame(FrameLen::Total(1), binary)),
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

/// What C's lib2700 traces as it echoes test 2700's frames, the
/// connection only connected: C's own trace, from its log.
const TRACE_2700: &[&str] = &[
    "[WS] curl_ws_recv, added 31 bytes from network",
    "[WS] decoded head [TEXT payload=0/3]",
    "[WS] decoded passing [TEXT payload=0/3]",
    "[WS] curl_ws_recv(len=0) -> 0 bytes (frame at 0, 3 left)",
    "[WS] curl_ws_send(len=0, fragsize=3, flags=21), raw=0",
    "[WS] WS-ENC: sending [TEXT payload=0/3]",
    "[WS] flushed 6 bytes",
    "[WS] curl_ws_send(len=0, fragsize=3, flags=21, raw=0) -> 0, 0",
    "[WS] passed 3 bytes payload, 0 remain",
    "[WS] decoded passing [TEXT payload=3/3]",
    "[WS] curl_ws_recv(len=256) -> 3 bytes (frame at 0, 0 left)",
    "[WS] curl_ws_send(len=3, fragsize=0, flags=1), raw=0",
    "[WS] WS-ENC: buffered [TEXT payload=3/3]",
    "[WS] flushed 3 bytes",
    "[WS] curl_ws_send(len=3, fragsize=0, flags=1, raw=0) -> 0, 3",
    "[WS] decoded head [BIN payload=0/3]",
    "[WS] decoded passing [BIN payload=0/3]",
    "[WS] curl_ws_recv(len=0) -> 0 bytes (frame at 0, 3 left)",
    "[WS] curl_ws_send(len=0, fragsize=3, flags=22), raw=0",
    "[WS] WS-ENC: sending [BIN payload=0/3]",
    "[WS] flushed 6 bytes",
    "[WS] curl_ws_send(len=0, fragsize=3, flags=22, raw=0) -> 0, 0",
    "[WS] passed 3 bytes payload, 0 remain",
    "[WS] decoded passing [BIN payload=3/3]",
    "[WS] curl_ws_recv(len=256) -> 3 bytes (frame at 0, 0 left)",
    "[WS] curl_ws_send(len=3, fragsize=0, flags=2), raw=0",
    "[WS] WS-ENC: buffered [BIN payload=3/3]",
    "[WS] flushed 3 bytes",
    "[WS] curl_ws_send(len=3, fragsize=0, flags=2, raw=0) -> 0, 3",
    "[WS] decoded head [PING payload=0/4]",
    "[WS] decoded passing [PING payload=0/4]",
    "[WS] curl_ws_recv(len=0) -> 0 bytes (frame at 0, 4 left)",
    "[WS] curl_ws_send(len=0, fragsize=4, flags=30), raw=0",
    "[WS] WS-ENC: sending [PING payload=0/4]",
    "[WS] flushed 6 bytes",
    "[WS] curl_ws_send(len=0, fragsize=4, flags=30, raw=0) -> 0, 0",
    "[WS] passed 4 bytes payload, 0 remain",
    "[WS] decoded passing [PING payload=4/4]",
    "[WS] curl_ws_recv(len=256) -> 4 bytes (frame at 0, 0 left)",
    "[WS] curl_ws_send(len=4, fragsize=0, flags=10), raw=0",
    "[WS] WS-ENC: buffered [PING payload=4/4]",
    "[WS] flushed 4 bytes",
    "[WS] curl_ws_send(len=4, fragsize=0, flags=10, raw=0) -> 0, 4",
    "[WS] decoded head [PONG payload=0/4]",
    "[WS] decoded passing [PONG payload=0/4]",
    "[WS] curl_ws_recv(len=0) -> 0 bytes (frame at 0, 4 left)",
    "[WS] curl_ws_send(len=0, fragsize=4, flags=60), raw=0",
    "[WS] WS-ENC: sending [PONG payload=0/4]",
    "[WS] flushed 6 bytes",
    "[WS] curl_ws_send(len=0, fragsize=4, flags=60, raw=0) -> 0, 0",
    "[WS] passed 4 bytes payload, 0 remain",
    "[WS] decoded passing [PONG payload=4/4]",
    "[WS] curl_ws_recv(len=256) -> 4 bytes (frame at 0, 0 left)",
    "[WS] curl_ws_send(len=4, fragsize=0, flags=40), raw=0",
    "[WS] WS-ENC: buffered [PONG payload=4/4]",
    "[WS] flushed 4 bytes",
    "[WS] curl_ws_send(len=4, fragsize=0, flags=40, raw=0) -> 0, 4",
    "[WS] decoded head [CLOSE payload=0/7]",
    "[WS] decoded passing [CLOSE payload=0/7]",
    "[WS] curl_ws_recv(len=0) -> 0 bytes (frame at 0, 7 left)",
    "[WS] curl_ws_send(len=0, fragsize=7, flags=28), raw=0",
    "[WS] WS-ENC: sending [CLOSE payload=0/7]",
    "[WS] flushed 6 bytes",
    "[WS] curl_ws_send(len=0, fragsize=7, flags=28, raw=0) -> 0, 0",
    "[WS] passed 7 bytes payload, 0 remain",
    "[WS] decoded passing [CLOSE payload=7/7]",
    "[WS] curl_ws_recv(len=256) -> 7 bytes (frame at 0, 0 left)",
    "[WS] curl_ws_send(len=7, fragsize=0, flags=8), raw=0",
    "[WS] WS-ENC: buffered [CLOSE payload=7/7]",
    "[WS] flushed 7 bytes",
    "[WS] curl_ws_send(len=7, fragsize=0, flags=8, raw=0) -> 0, 7",
];

/// lib2700's echo of every frame on the codec: each frame's head read
/// with a receive of nothing and its echo started with its length, then
/// its payload received and sent back, until the close; the trace is C's
/// line for line, and the frames sent are test 2700's.
#[test]
fn an_echo_traces_as_c_s_lib2700() {
    let mut rec = Rec {
        incoming: b"\x81\x03txt\x82\x03bin\x89\x04ping\x8a\x04pong\x88\x07\x03\xe8close".to_vec(),
        ..Rec::default()
    };
    let mut ws = WsConn::new(&mut rec).unwrap();
    ws.debugging.zero_mask = true;
    rec.lines.clear();
    loop {
        let Ok(crate::ws::Received::Frame(head)) =
            api_recv(&mut ws, &mut rec, &mut [], false, false, false)
        else {
            panic!("a frame's head");
        };
        let flags = SendFlags {
            kind: Some(head.kind.kind),
            more: head.kind.more,
        };
        let mut left = head.bytes_left;
        assert_eq!(
            api_send(
                &mut ws,
                &mut rec,
                false,
                b"",
                FrameLen::Total(left),
                flags,
                false
            ),
            Ok(crate::ws::Sent::Bytes(0))
        );
        while left > 0 {
            let mut buf = [0u8; 256];
            let Ok(crate::ws::Received::Frame(got)) =
                api_recv(&mut ws, &mut rec, &mut buf, false, false, false)
            else {
                panic!("a frame's payload");
            };
            left -= got.len as u64;
            assert_eq!(got.bytes_left, left);
            assert_eq!(
                api_send(
                    &mut ws,
                    &mut rec,
                    false,
                    &buf[..got.len],
                    FrameLen::These,
                    flags,
                    false
                ),
                Ok(crate::ws::Sent::Bytes(got.len))
            );
        }
        if head.kind.kind == FrameKind::Close {
            break;
        }
    }
    assert_eq!(rec.lines, TRACE_2700);
    assert_eq!(
        rec.sent,
        b"\x81\x83\0\0\0\0txt\x82\x83\0\0\0\0bin\x89\x84\0\0\0\0ping\
\x8a\x84\0\0\0\0pong\x88\x87\0\0\0\0\x03\xe8close"
    );
}

/// Test 2708 on the codec: a receive answers the ping before it with a
/// pong as it reads the close, and sends the pong before the close the
/// application sends back; C's trace of it, line for line.
#[test]
fn a_ping_before_a_close_traces_as_c_s_2708() {
    let mut rec = Rec {
        incoming: b"\x89\x04test\x88\x00".to_vec(),
        ..Rec::default()
    };
    let mut ws = WsConn::new(&mut rec).unwrap();
    ws.debugging.zero_mask = true;
    rec.lines.clear();
    let Ok(crate::ws::Received::Frame(close)) =
        api_recv(&mut ws, &mut rec, &mut [], false, true, false)
    else {
        panic!("the close");
    };
    assert_eq!(close.kind.kind, FrameKind::Close);
    let flags = SendFlags {
        kind: Some(FrameKind::Close),
        more: false,
    };
    assert_eq!(
        api_send(
            &mut ws,
            &mut rec,
            false,
            b"",
            FrameLen::Total(0),
            flags,
            false
        ),
        Ok(crate::ws::Sent::Bytes(0))
    );
    assert_eq!(
        rec.lines,
        [
            "[WS] curl_ws_recv, added 8 bytes from network",
            "[WS] decoded head [PING payload=0/4]",
            "[WS] auto PONG to [PING payload=0/4]",
            "[WS] passed 4 bytes payload, 0 remain",
            "[WS] decoded passing [PING payload=4/4]",
            "[WS] decoded head [CLOSE payload=0/0]",
            "[WS] curl_ws_recv(len=0) -> 0 bytes (frame at 0, 0 left)",
            "[WS] WS-ENC: sending [PONG payload=0/4]",
            "[WS] WS-ENC: buffered [PONG payload=4/4]",
            "[WS] flushed 10 bytes",
            "[WS] curl_ws_send(len=0, fragsize=0, flags=28), raw=0",
            "[WS] WS-ENC: sending [CLOSE payload=0/0]",
            "[WS] flushed 6 bytes",
            "[WS] curl_ws_send(len=0, fragsize=0, flags=28, raw=0) -> 0, 0",
        ]
    );
    assert_eq!(rec.sent, b"\x8a\x84\0\0\0\0test\x88\x80\0\0\0\0");
}

/// A head that comes a byte at a time is traced as C traces it while it
/// waits for more: its opcode alone, how much of it is read, then the
/// frame it names, none of its payload come.
#[test]
fn a_head_read_in_pieces_is_traced_as_it_comes() {
    let mut incoming = b"\x81\x7e\x00\x80".to_vec();
    incoming.extend_from_slice(&[b'x'; 128]);
    let mut rec = Rec {
        incoming,
        piece: Some(1),
        ..Rec::default()
    };
    let mut ws = WsConn::new(&mut rec).unwrap();
    rec.lines.clear();
    let mut buf = [0u8; 256];
    let got = api_recv(&mut ws, &mut rec, &mut buf, false, true, false);
    let Ok(crate::ws::Received::Frame(frame)) = got else {
        panic!("{got:?}");
    };
    assert_eq!((frame.len, frame.bytes_left), (1, 127));
    let waits: Vec<&String> = rec
        .lines
        .iter()
        .filter(|l| l.contains("need more input"))
        .collect();
    assert_eq!(
        waits,
        [
            "[WS] decoded need more input [TEXT]",
            "[WS] decoded need more input [TEXT](2/4)",
            "[WS] decoded need more input [TEXT](3/4)",
            "[WS] decoded need more input [TEXT payload=0/128]",
        ]
    );
}

/// A decoder that refused a frame starts over: the next frame is read
/// from its first byte (`ws_dec_reset`).
#[test]
fn a_refused_frame_leaves_the_decoder_as_new() {
    let mut dec = Decoder::default();
    let mut q = ChunkQueue::new(CHUNK_SIZE, 1);
    let mut frames = Frames::default();
    q.write(b"\x89\x7e\x00\x7e").unwrap();
    assert!(matches!(
        dec.pass(&mut q, &mut frames),
        Err(Stop::Failed(_))
    ));
    q.reset();
    q.write(b"\x81\x01x").unwrap();
    assert!(matches!(dec.pass(&mut q, &mut frames), Ok(Passed::Frame)));
    assert_eq!(frames.got, [(ft(FrameKind::Text, false), b"x".to_vec())]);
}

/// A new frame is refused while the last one's payload is still owed,
/// and a control frame of 125 bytes is the longest sent; a pong's and a
/// close's refusals name them.
#[test]
fn an_encoder_refuses_what_c_refuses() {
    let mut rec = Rec::default();
    let mut enc = Encoder::default();
    let mut out = ChunkQueue::new(CHUNK_SIZE, 2);
    enc.add_frame(&mut rec, text(), 3, &mut out, false).unwrap();
    assert_eq!(
        enc.add_frame(&mut rec, text(), 1, &mut out, false),
        Err(ErrorKind::SendError)
    );
    assert_eq!(
        rec.failed,
        ["[WS] starting new frame with 3 bytes from last one remaining to be sent"]
    );
    rec.failed.clear();
    for (kind, name) in [
        (FrameKind::Ping, "PING"),
        (FrameKind::Pong, "PONG"),
        (FrameKind::Close, "CLOSE"),
    ] {
        let flags = SendFlags {
            kind: Some(kind),
            more: false,
        };
        let mut enc = Encoder::default();
        let mut out = ChunkQueue::new(CHUNK_SIZE, 2);
        assert_eq!(enc.add_frame(&mut rec, flags, 125, &mut out, false), Ok(()));
        let mut enc = Encoder::default();
        assert_eq!(
            enc.add_frame(&mut rec, flags, 126, &mut out, false),
            Err(ErrorKind::TooLarge)
        );
        assert_eq!(
            rec.failed.pop().unwrap(),
            format!("[WS] given {name} frame is too big")
        );
    }
}

/// A frame's length past 125 is said in 16 bits after 126, past 65535
/// in 64 bits after 127, the mask bit set on each.
#[test]
fn long_lengths_are_sent_as_rfc_6455_says() {
    let mut rec = Rec::default();
    for (len, head) in [
        (126u64, vec![0x81, 0xfe, 0x00, 0x7e]),
        (65535, vec![0x81, 0xfe, 0xff, 0xff]),
        (65536, vec![0x81, 0xff, 0, 0, 0, 0, 0, 1, 0, 0]),
    ] {
        let mut enc = Encoder::default();
        let mut out = ChunkQueue::new(CHUNK_SIZE, 2);
        enc.add_frame(&mut rec, text(), len, &mut out, true)
            .unwrap();
        let mut got = vec![0u8; out.len()];
        out.read(&mut got);
        assert_eq!(got[..head.len()], head[..], "{len}");
    }
}

/// Raw, the bytes go as they are, after what was encoded before; a
/// connection that takes none says to try again.
#[test]
fn a_raw_send_goes_as_it_is() {
    let mut rec = Rec::default();
    let mut ws = WsConn::new(&mut rec).unwrap();
    let none = SendFlags {
        kind: None,
        more: false,
    };
    assert_eq!(
        api_send(
            &mut ws,
            &mut rec,
            true,
            b"abc",
            FrameLen::These,
            none,
            false
        ),
        Ok(crate::ws::Sent::Bytes(3))
    );
    assert_eq!(rec.sent, b"abc");
    rec.takes = Some(0);
    assert_eq!(
        api_send(&mut ws, &mut rec, true, b"de", FrameLen::These, none, false),
        Ok(crate::ws::Sent::WouldBlock)
    );
    rec.takes = Some(1);
    assert_eq!(
        api_send(&mut ws, &mut rec, true, b"de", FrameLen::These, none, false),
        Ok(crate::ws::Sent::Bytes(1))
    );
    assert_eq!(rec.sent, b"abcd");
}

/// A send buffer exactly one chunk full takes no pong at a flush: it
/// waits for the room the buffer's chunk has (`ws_flush`).
#[test]
fn a_full_send_buffer_takes_no_pong() {
    let mut rec = Rec {
        takes: Some(0),
        ..Rec::default()
    };
    let mut ws = WsConn::new(&mut rec).unwrap();
    ws.sendbuf = ChunkQueue::new(8, 2);
    ws.sendbuf.write(&[0; 8]).unwrap();
    ws.add_pong(b"p");
    assert_eq!(ws.flush(&mut rec, false), Err(Stop::Again));
    assert!(ws.pending(), "no room for the pong");
    rec.takes = None;
    assert_eq!(ws.flush(&mut rec, false), Ok(()));
    assert_eq!(rec.sent.len(), 8);
    assert_eq!(ws.flush(&mut rec, false), Ok(()));
    assert!(!ws.pending());
    assert_eq!(rec.sent[8..10], [0x8a, 0x81]);
}

/// The debug build's chunk limit cuts a send only of a chunk longer than
/// it: a chunk as long goes whole, and the next with it.
#[test]
fn a_chunk_as_long_as_the_debug_limit_goes_whole() {
    let mut rec = Rec::default();
    let mut ws = WsConn::new(&mut rec).unwrap();
    ws.sendbuf = ChunkQueue::new(4, 2);
    ws.sendbuf.write(b"abcdefgh").unwrap();
    ws.debugging.chunk_eagain = 4;
    assert_eq!(ws.flush(&mut rec, false), Ok(()));
    assert_eq!(rec.sent, b"abcdefgh");
}

/// A send buffer with room left in its chunk takes the pong at a flush,
/// behind what it holds, though the connection takes nothing yet.
#[test]
fn a_send_buffer_with_room_takes_the_pong() {
    let mut rec = Rec {
        takes: Some(0),
        ..Rec::default()
    };
    let mut ws = WsConn::new(&mut rec).unwrap();
    ws.sendbuf = ChunkQueue::new(16, 2);
    ws.sendbuf.write(&[0; 3]).unwrap();
    ws.add_pong(b"p");
    assert_eq!(ws.flush(&mut rec, false), Err(Stop::Again));
    assert!(!ws.pending(), "the pong went into the buffer");
    assert_eq!(ws.sendbuf.len(), 3 + 6 + 1);
}

/// The debug build's sizes are decimal numbers of at most a MiB, as C
/// reads them (`curlx_str_number`); anything else is not one.
#[test]
fn debug_sizes_are_at_most_a_mib() {
    assert_eq!(curl_number(b"1048576", DEBUG_MAX), Some(1_048_576));
    assert_eq!(curl_number(b"1048577", DEBUG_MAX), None);
    assert_eq!(curl_number(b"12x", DEBUG_MAX), Some(12));
    assert_eq!(curl_number(b"x12", DEBUG_MAX), None);
    assert_eq!(curl_number(b"", DEBUG_MAX), None);
}

/// A length of 63 bits, its top bit clear, is a length: the frame waits
/// for its payload, refused for nothing.
#[test]
fn a_63_bit_length_is_taken() {
    let (got, failed) = decode(b"\x82\x7f\x7f\xff\xff\xff\xff\xff\xff\xffab");
    assert_eq!(failed, None);
    assert_eq!(got.iter().map(|(_, b)| b.len()).sum::<usize>(), 2);
}

/// A frame's payload held over two chunks fills the buffer from both,
/// no more than it has room for, the rest left for the next receive.
#[test]
fn a_receive_fills_its_buffer_from_more_than_one_chunk() {
    let mut rec = Rec::default();
    let mut ws = WsConn::new(&mut rec).unwrap();
    ws.recvbuf = ChunkQueue::new(4, 4);
    rec.incoming = b"\x82\x06abcdef".to_vec();
    let mut buf = [0u8; 3];
    let frame = ws.recv(&mut rec, &mut buf, true).unwrap();
    assert_eq!(&buf[..frame.len], b"abc");
    assert_eq!((frame.offset, frame.bytes_left), (0, 3));
    let frame = ws.recv(&mut rec, &mut buf, true).unwrap();
    assert_eq!(&buf[..frame.len], b"def");
    assert_eq!((frame.offset, frame.bytes_left), (3, 0));
}

/// A ping that comes a byte at a time is handed on as it comes, as C's
/// is, and answered once its last byte is in: the pong is of that piece.
#[test]
fn a_ping_in_pieces_is_answered_at_its_last() {
    let mut rec = Rec {
        piece: Some(1),
        ..Rec::default()
    };
    let mut ws = WsConn::new(&mut rec).unwrap();
    rec.incoming = b"\x89\x02hi\x81\x01x".to_vec();
    let mut buf = [0u8; 16];
    let frame = ws.recv(&mut rec, &mut buf, true).unwrap();
    assert_eq!(frame.kind, ft(FrameKind::Ping, false));
    assert_eq!((&buf[..frame.len], frame.bytes_left), (&b"h"[..], 1));
    assert!(!ws.pending());
    let frame = ws.recv(&mut rec, &mut buf, true).unwrap();
    assert_eq!(
        frame.kind,
        ft(FrameKind::Text, false),
        "the ping's end taken"
    );
    assert_eq!(&buf[..frame.len], b"x");
    assert!(ws.pending());
}

/// A frame started while one is under way is refused with C's reason.
#[test]
fn a_frame_started_over_another_says_why() {
    let mut rec = Rec::default();
    let mut ws = WsConn::new(&mut rec).unwrap();
    let binary = SendFlags {
        kind: Some(FrameKind::Binary),
        more: false,
    };
    assert_eq!(
        ws.start_frame(&mut rec, AskedFrame::Frame(FrameLen::Total(2), binary)),
        Ok(())
    );
    assert_eq!(
        ws.start_frame(&mut rec, AskedFrame::Frame(FrameLen::Total(2), binary)),
        Err(ErrorKind::SendError)
    );
    assert_eq!(rec.failed, ["[WS] previous frame not finished"]);
}

/// With no pong waiting, a receive sends nothing of what the send
/// buffer holds: only a pong added is flushed after it, as C's.
#[test]
fn a_receive_flushes_only_for_a_pong() {
    let mut rec = Rec::default();
    let mut ws = WsConn::new(&mut rec).unwrap();
    ws.sendbuf.write(b"zz").unwrap();
    rec.incoming = b"\x81\x01x".to_vec();
    ws.recv(&mut rec, &mut [0u8; 4], true).unwrap();
    ws.send_pending(&mut rec, false);
    assert_eq!(rec.sent, b"");
}

/// A continuation's head is traced by its name, as C's.
#[test]
fn a_continuation_is_traced_as_cont() {
    let mut rec = Rec::default();
    let mut ws = WsConn::new(&mut rec).unwrap();
    rec.incoming = b"\x01\x01a\x80\x01b".to_vec();
    let mut buf = [0u8; 4];
    ws.recv(&mut rec, &mut buf, true).unwrap();
    ws.recv(&mut rec, &mut buf, true).unwrap();
    let head = "[WS] decoded head [CONT payload=0/1]";
    assert!(rec.lines.iter().any(|l| l == head), "{:#?}", rec.lines);
}

/// A send blocked once its head went, none of its payload with it, is to
/// be given again: a send of none is no answer. One byte of it gone is a
/// send of that byte.
#[test]
fn a_send_blocked_after_its_head_is_given_again() {
    let text = SendFlags {
        kind: Some(FrameKind::Text),
        more: false,
    };
    let mut rec = Rec {
        takes: Some(6),
        ..Rec::default()
    };
    let mut ws = WsConn::new(&mut rec).unwrap();
    let sent = ws.send(&mut rec, b"abc", FrameLen::These, text, false);
    assert_eq!(sent, Err(Stop::Again));
    let said = "[WS] EAGAIN flushing sendbuf, payload_encoded: 3/3";
    assert!(rec.lines.iter().any(|l| l == said), "{:#?}", rec.lines);
    let mut rec = Rec {
        takes: Some(7),
        ..Rec::default()
    };
    let mut ws = WsConn::new(&mut rec).unwrap();
    let sent = ws.send(&mut rec, b"abc", FrameLen::These, text, false);
    assert_eq!(sent, Ok(1));
}

/// A send that blocks says what of it went: none is a send to give again;
/// some, gone before the block, is a count with the block to follow
/// (`curl_ws_send` returning `CURLE_AGAIN` with its `sent` set).
#[test]
fn a_blocked_send_counts_what_went_before() {
    let flags = text();
    let mut rec = Rec {
        takes: Some(6),
        ..Rec::default()
    };
    let mut ws = WsConn::new(&mut rec).unwrap();
    let sent = api_send(
        &mut ws,
        &mut rec,
        false,
        b"abc",
        FrameLen::These,
        flags,
        false,
    );
    assert_eq!(sent, Ok(Sent::WouldBlock), "only the head went");
    // Bytes past the frame's end stop the send with the frame's gone.
    let mut rec = Rec::default();
    let mut ws = WsConn::new(&mut rec).unwrap();
    let sent = api_send(
        &mut ws,
        &mut rec,
        false,
        b"abcde",
        FrameLen::Total(3),
        flags,
        false,
    );
    assert_eq!(sent, Ok(Sent::BytesThenWouldBlock(3)));
}

/// C's line on entering `curl_ws_start_frame` has no closing parenthesis.
#[test]
fn a_frame_s_start_is_said_as_c_says_it() {
    let asked = start_asked_of(text(), 5);
    let mut said = String::new();
    start_enters(&asked, |line| said = line.to_string());
    assert_eq!(said, "curl_ws_start_frame(flags=1, frame_len=5");
}

/// Raw, a send names no frame: a size given, even of none, is refused.
#[test]
fn a_raw_send_with_a_size_is_refused() {
    let mut rec = Rec::default();
    let mut ws = WsConn::new(&mut rec).unwrap();
    let none = SendFlags {
        kind: None,
        more: false,
    };
    let sent = api_send(
        &mut ws,
        &mut rec,
        true,
        b"x",
        FrameLen::Total(0),
        none,
        false,
    );
    assert_eq!(sent, Err(ErrorKind::BadFunctionArgument));
    assert_eq!(
        rec.failed,
        ["[WS] fragsize and flags must be zero in raw mode"]
    );
    assert_eq!(rec.sent, b"");
}

/// A frame's start refused still leaves the pong waiting encoded, as its
/// head would have (`ws_enc_write_head`), and says why after it.
#[test]
fn a_refused_frame_start_encodes_the_pong_waiting() {
    let mut rec = Rec::default();
    let mut ws = WsConn::new(&mut rec).unwrap();
    ws.add_pong(b"p");
    let asked = Asked {
        length: 1,
        flags: 3,
        frame: AskedFrame::None(crate::ws::Refusal {
            kind: ErrorKind::BadFunctionArgument,
            why: "[WS] unknown flags: 3",
        }),
    };
    let started = super::api_start_frame(&mut ws, &mut rec, &asked);
    assert_eq!(started, Err(ErrorKind::BadFunctionArgument));
    assert_eq!(rec.failed, ["[WS] unknown flags: 3"]);
    assert!(!ws.sendbuf_mut().is_empty(), "the pong is encoded");
    assert!(!ws.pending());
}
