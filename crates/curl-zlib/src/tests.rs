use std::cell::Cell;
use std::fmt;

use super::*;

thread_local! {
    /// The blocks zlib holds of what it allocated on this thread.
    pub(super) static ZLIB_BLOCKS: Cell<usize> = const { Cell::new(0) };
}

fn zlib_blocks() -> usize {
    ZLIB_BLOCKS.with(Cell::get)
}

/// What a decoder made, in the pieces it made it, and what it said.
#[derive(Default)]
struct Collect {
    pieces: Vec<Vec<u8>>,
    said: Vec<(ErrorKind, String)>,
    time_up: bool,
}

impl Collect {
    fn made(&self) -> Vec<u8> {
        self.pieces.concat()
    }
}

impl Sink for Collect {
    fn write(&mut self, bytes: &[u8]) -> Result<(), ErrorKind> {
        self.pieces.push(bytes.to_vec());
        Ok(())
    }

    fn timed_out(&self) -> bool {
        self.time_up
    }

    fn fail(&mut self, kind: ErrorKind, said: fmt::Arguments<'_>) -> ErrorKind {
        self.said.push((kind, said.to_string()));
        kind
    }
}

const HELLO: &[u8] = b"hello, world\n";
const GZIP_HELLO: &[u8] = b"\x1f\x8b\x08\x00\x00\x00\x00\x00\x02\xff\xcb\x48\xcd\xc9\xc9\xd7\x51\x28\xcf\x2f\xca\x49\xe1\x02\x00\x53\x74\x24\xf4\x0d\x00\x00\x00";
const ZLIB_HELLO: &[u8] =
    b"\x78\x9c\xcb\x48\xcd\xc9\xc9\xd7\x51\x28\xcf\x2f\xca\x49\xe1\x02\x00\x21\xe7\x04\x93";
const RAW_HELLO: &[u8] = b"\xcb\x48\xcd\xc9\xc9\xd7\x51\x28\xcf\x2f\xca\x49\xe1\x02\x00";

/// `data` as a raw deflate stream of stored blocks.
fn stored(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    let blocks: Vec<&[u8]> = data.chunks(65535).collect();
    for (i, block) in blocks.iter().enumerate() {
        out.push(u8::from(i + 1 == blocks.len()));
        let len = block.len() as u16;
        out.extend_from_slice(&len.to_le_bytes());
        out.extend_from_slice(&(!len).to_le_bytes());
        out.extend_from_slice(block);
    }
    out
}

fn crc32(data: &[u8]) -> u32 {
    let mut crc = !0u32;
    for &b in data {
        crc ^= u32::from(b);
        for _ in 0..8 {
            crc = if crc & 1 == 1 {
                (crc >> 1) ^ 0xedb8_8320
            } else {
                crc >> 1
            };
        }
    }
    !crc
}

/// `data` in gzip's framing, its deflate stream of stored blocks.
fn gzipped(data: &[u8]) -> Vec<u8> {
    let mut out = b"\x1f\x8b\x08\x00\x00\x00\x00\x00\x00\xff".to_vec();
    out.extend(stored(data));
    out.extend_from_slice(&crc32(data).to_le_bytes());
    out.extend_from_slice(&(data.len() as u32).to_le_bytes());
    out
}

fn decode(make: MakeDecoder, input: &[u8]) -> (Result<(), ErrorKind>, Collect) {
    let mut out = Collect::default();
    let mut d = make().unwrap();
    let r = d.decode(input, &mut out);
    (r, out)
}

type MakeDecoder = fn() -> Result<Box<dyn Decoder>, ErrorKind>;

#[test]
fn the_codings_are_undone() {
    let (r, out) = decode(gzip, GZIP_HELLO);
    assert_eq!((r, out.made()), (Ok(()), HELLO.to_vec()));
    let (r, out) = decode(deflate, ZLIB_HELLO);
    assert_eq!((r, out.made()), (Ok(()), HELLO.to_vec()));
}

/// A body fed a byte at a time makes the same.
#[test]
fn a_body_in_pieces_makes_the_same() {
    for (make, input) in [(gzip as MakeDecoder, GZIP_HELLO), (deflate, ZLIB_HELLO)] {
        let mut out = Collect::default();
        let mut d = make().unwrap();
        for b in input {
            d.decode(std::slice::from_ref(b), &mut out).unwrap();
        }
        assert_eq!(out.made(), HELLO);
    }
}

/// A `deflate` body without zlib's framing is read as raw deflate, with up
/// to 4 bytes after it let by (`Z_DATA_ERROR` at `ZLIB_INIT`).
#[test]
fn a_raw_deflate_body_is_read_as_one() {
    let (r, out) = decode(deflate, RAW_HELLO);
    assert_eq!((r, out.made()), (Ok(()), HELLO.to_vec()));
    let mut four = RAW_HELLO.to_vec();
    four.extend_from_slice(b"abcd");
    assert_eq!(decode(deflate, &four).0, Ok(()));
    let mut five = RAW_HELLO.to_vec();
    five.extend_from_slice(b"abcde");
    let (r, out) = decode(deflate, &five);
    assert_eq!(r, Err(ErrorKind::WriteError));
    assert!(out.said.is_empty(), "{:?}", out.said);
    // Only in its first piece: here zlib's framing and a stored block's
    // length came first, and what follows, though raw deflate itself, is
    // not that block.
    let mut out = Collect::default();
    let mut d = deflate().unwrap();
    d.decode(b"\x78\x01\x01\x05\x00", &mut out).unwrap();
    assert_eq!(
        d.decode(RAW_HELLO, &mut out),
        Err(ErrorKind::BadContentEncoding)
    );
    assert!(out.made().is_empty());
}

#[test]
fn a_second_gzip_member_is_refused() {
    let two = [GZIP_HELLO, GZIP_HELLO].concat();
    let (r, out) = decode(gzip, &two);
    assert_eq!(r, Err(ErrorKind::WriteError));
    assert_eq!(out.made(), HELLO);
    assert_eq!(
        out.said,
        [(
            ErrorKind::WriteError,
            "Multi-member gzip response not supported".to_string()
        )]
    );
}

/// Anything after the stream is an error nothing says; so is more body.
#[test]
fn bytes_after_the_stream_fail_it() {
    let mut more = GZIP_HELLO.to_vec();
    more.push(b'x');
    let (r, out) = decode(gzip, &more);
    assert_eq!((r, out.said.len()), (Err(ErrorKind::WriteError), 0));
    let mut out = Collect::default();
    let mut d = gzip().unwrap();
    d.decode(GZIP_HELLO, &mut out).unwrap();
    assert_eq!(d.decode(b"x", &mut out), Err(ErrorKind::WriteError));
}

#[test]
fn a_body_not_of_the_coding_fails_with_zlib_s_words() {
    let (r, out) = decode(gzip, b"this is not gzip at all");
    assert_eq!(r, Err(ErrorKind::BadContentEncoding));
    assert_eq!(
        out.said,
        [(
            ErrorKind::BadContentEncoding,
            "Error while processing content unencoding: incorrect header check".to_string()
        )]
    );
}

/// What is made goes on a buffer of at most 16 KiB at a time.
#[test]
fn output_goes_in_pieces_of_at_most_16_kib() {
    let data: Vec<u8> = (0..200_000u32).map(|i| (i % 251) as u8).collect();
    let (r, out) = decode(gzip, &gzipped(&data));
    assert_eq!(r, Ok(()));
    assert!(out.pieces.iter().all(|p| p.len() <= BUFFER));
    assert!(out.pieces.iter().any(|p| p.len() == BUFFER));
    assert_eq!(out.made(), data);
}

/// The time is checked every 1 MiB made.
#[test]
fn a_transfer_out_of_time_stops_decoding() {
    let data = vec![7u8; 3 * 1024 * 1024];
    let mut out = Collect {
        time_up: true,
        ..Collect::default()
    };
    let mut d = gzip().unwrap();
    let r = d.decode(&gzipped(&data), &mut out);
    assert_eq!(r, Err(ErrorKind::OperationTimedout));
    // 64 rounds of at most a buffer each, the 65th checks the time.
    let made = out.made().len();
    assert!((62 * BUFFER..=64 * BUFFER).contains(&made), "{made}");
    assert_eq!(
        out.said,
        [(
            ErrorKind::OperationTimedout,
            "Operation timed out while decoding payload".to_string()
        )]
    );
}

#[test]
fn the_version_is_the_library_s() {
    assert!(version().starts_with("1."), "{}", version());
}

/// zlib's memory goes as soon as a stream ends or fails, as `exit_zlib`
/// frees it, not when the decoder goes; and a decoder dropped mid-stream
/// frees it too.
#[test]
fn a_stream_frees_zlib_s_memory_when_it_ends() {
    let mut five = RAW_HELLO.to_vec();
    five.extend_from_slice(b"abcde");
    let mut four = RAW_HELLO.to_vec();
    four.extend_from_slice(b"abcd");
    let two = [GZIP_HELLO, GZIP_HELLO].concat();
    let cases: [(MakeDecoder, &[u8], Result<(), ErrorKind>); 6] = [
        (gzip, GZIP_HELLO, Ok(())),
        (deflate, ZLIB_HELLO, Ok(())),
        (deflate, &four, Ok(())),
        (deflate, &five, Err(ErrorKind::WriteError)),
        (gzip, &two, Err(ErrorKind::WriteError)),
        (
            gzip,
            b"this is not gzip",
            Err(ErrorKind::BadContentEncoding),
        ),
    ];
    for (i, (make, input, result)) in cases.into_iter().enumerate() {
        let mut d = make().unwrap();
        assert!(zlib_blocks() > 0, "case {i}: zlib's state is allocated");
        assert_eq!(d.decode(input, &mut Collect::default()), result, "case {i}");
        assert_eq!(zlib_blocks(), 0, "case {i}: freed as the stream ends");
        drop(d);
        assert_eq!(zlib_blocks(), 0, "case {i}: and only once");
    }
    for (make, input) in [(gzip as MakeDecoder, GZIP_HELLO), (deflate, ZLIB_HELLO)] {
        let mut d = make().unwrap();
        let half = &input[..input.len() / 2];
        assert_eq!(d.decode(half, &mut Collect::default()), Ok(()));
        assert!(zlib_blocks() > 0);
        drop(d);
        assert_eq!(zlib_blocks(), 0, "freed with the decoder");
    }
}

/// The 4 bytes let by after a raw stream may come a piece at a time; the
/// fifth fails.
#[test]
fn a_raw_stream_s_trailer_may_come_in_pieces() {
    let mut out = Collect::default();
    let mut d = deflate().unwrap();
    let mut first = RAW_HELLO.to_vec();
    first.extend_from_slice(b"ab");
    assert_eq!(d.decode(&first, &mut out), Ok(()));
    assert_eq!(d.decode(b"c", &mut out), Ok(()));
    assert_eq!(d.decode(b"d", &mut out), Ok(()));
    assert_eq!(d.decode(b"e", &mut out), Err(ErrorKind::WriteError));
    assert_eq!(out.made(), HELLO);
}

/// What zlib made in a round that failed is not passed on, and no round
/// passes on nothing.
#[test]
fn a_failing_round_passes_nothing_on() {
    // gzip's framing around a fixed-code block of "hello" and a copy from
    // further back than anything made: zlib makes the five bytes, then
    // fails in the same round.
    let mut far = b"\x1f\x8b\x08\x00\x00\x00\x00\x00\x00\xff".to_vec();
    far.extend_from_slice(b"\xcb\x48\xcd\xc9\xc9\x07\x0a\x00\x00");
    let (r, out) = decode(gzip, &far);
    assert_eq!(r, Err(ErrorKind::BadContentEncoding));
    assert!(out.pieces.is_empty(), "{:?}", out.pieces);
    assert_eq!(
        out.said,
        [(
            ErrorKind::BadContentEncoding,
            "Error while processing content unencoding: invalid distance too far back".to_string()
        )]
    );
}
