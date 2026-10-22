use std::fmt;

use super::*;

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
const ZSTD_HELLO: &[u8] =
    b"\x28\xb5\x2f\xfd\x20\x0d\x69\x00\x00\x68\x65\x6c\x6c\x6f\x2c\x20\x77\x6f\x72\x6c\x64\x0a";
/// 300000 bytes of `q`.
const ZSTD_BIG: &[u8] = b"\x28\xb5\x2f\xfd\xa0\xe0\x93\x04\x00\x54\x00\x00\x10\x71\x71\x01\x00\xfb\xff\x39\xc0\x02\x02\x00\x10\x71\x03\x9f\x04\x71";

fn decode(input: &[u8]) -> (Result<(), ErrorKind>, Collect) {
    let mut out = Collect::default();
    let r = decoder().unwrap().decode(input, &mut out);
    (r, out)
}

#[test]
fn the_coding_is_undone() {
    let (r, out) = decode(ZSTD_HELLO);
    assert_eq!((r, out.made()), (Ok(()), HELLO.to_vec()));
    let mut out = Collect::default();
    let mut d = decoder().unwrap();
    for b in ZSTD_HELLO {
        d.decode(std::slice::from_ref(b), &mut out).unwrap();
    }
    assert_eq!(out.made(), HELLO);
}

/// What is made goes on a buffer of at most 16 KiB at a time, a full one
/// asking for another round.
#[test]
fn output_goes_in_pieces_of_at_most_16_kib() {
    let (r, out) = decode(ZSTD_BIG);
    assert_eq!(r, Ok(()));
    assert!(out.pieces.iter().all(|p| p.len() <= BUFFER));
    assert_eq!(out.pieces[0].len(), BUFFER);
    assert_eq!(out.made(), vec![b'q'; 300_000]);
    // Its input all read, a stream that filled the buffer has more to
    // make: here the first block, of 128 KiB, ends the input.
    let mut out = Collect::default();
    let mut d = decoder().unwrap();
    d.decode(&ZSTD_BIG[..22], &mut out).unwrap();
    assert_eq!(out.made().len(), 131_072);
}

/// A body not of the coding fails, silently.
#[test]
fn a_body_not_of_the_coding_fails() {
    let (r, out) = decode(b"this is not zstd");
    assert_eq!((r, out.said.len()), (Err(ErrorKind::BadContentEncoding), 0));
    let mut after = ZSTD_HELLO.to_vec();
    after.extend_from_slice(b"junk");
    assert_eq!(decode(&after).0, Err(ErrorKind::BadContentEncoding));
}

/// The time is checked every 1 MiB made.
#[test]
fn a_transfer_out_of_time_stops_decoding() {
    let mut data = Vec::new();
    for _ in 0..12 {
        data.extend_from_slice(ZSTD_BIG);
    }
    let mut out = Collect {
        time_up: true,
        ..Collect::default()
    };
    let r = decoder().unwrap().decode(&data, &mut out);
    assert_eq!(r, Err(ErrorKind::OperationTimedout));
    assert!(out.made().len() <= 64 * BUFFER, "{}", out.made().len());
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
    let v = version().to_string();
    assert!(v.starts_with("1."), "{v}");
}
