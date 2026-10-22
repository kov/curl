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
const BR_HELLO: &[u8] = b"\x21\x30\x00\x04\x68\x65\x6c\x6c\x6f\x2c\x20\x77\x6f\x72\x6c\x64\x0a\x03";
/// 300000 bytes of `q`.
const BR_BIG: &[u8] = b"\x55\xdf\x93\x04\x40\x22\x2e\x1e\x0b\x24\x73\x91\x00";
/// 3 MiB of `q`.
const BR_3M: &[u8] = b"\x9b\xff\xff\x2f\x00\x24\xe2\xe2\xb1\x40\x72\xef\x5f\x00";

fn decode(input: &[u8]) -> (Result<(), ErrorKind>, Collect) {
    let mut out = Collect::default();
    let r = decoder().unwrap().decode(input, &mut out);
    (r, out)
}

#[test]
fn the_coding_is_undone() {
    let (r, out) = decode(BR_HELLO);
    assert_eq!((r, out.made()), (Ok(()), HELLO.to_vec()));
    let mut out = Collect::default();
    let mut d = decoder().unwrap();
    for b in BR_HELLO {
        d.decode(std::slice::from_ref(b), &mut out).unwrap();
    }
    assert_eq!(out.made(), HELLO);
}

/// What is made goes on a buffer of at most 16 KiB at a time.
#[test]
fn output_goes_in_pieces_of_at_most_16_kib() {
    let (r, out) = decode(BR_BIG);
    assert_eq!(r, Ok(()));
    assert!(out.pieces.iter().all(|p| p.len() <= BUFFER));
    assert_eq!(out.pieces[0].len(), BUFFER);
    assert_eq!(out.made(), vec![b'q'; 300_000]);
}

/// After the stream's end, anything more fails, silently.
#[test]
fn bytes_after_the_stream_fail_it() {
    let mut more = BR_HELLO.to_vec();
    more.push(0);
    let (r, out) = decode(&more);
    assert_eq!((r, out.said.len()), (Err(ErrorKind::WriteError), 0));
    let mut out = Collect::default();
    let mut d = decoder().unwrap();
    d.decode(BR_HELLO, &mut out).unwrap();
    assert_eq!(d.decode(b"x", &mut out), Err(ErrorKind::WriteError));
}

/// brotli's error codes map as C maps them, silently.
#[test]
fn a_body_not_of_the_coding_fails() {
    // A window of reserved size, then padding brotli refuses.
    let (r, out) = decode(b"\xff\xff\xff\xff\xff\xff");
    assert!(r.is_err());
    assert!(out.said.is_empty());
    assert_eq!(map_error(-1), ErrorKind::BadContentEncoding);
    assert_eq!(map_error(-2), ErrorKind::WriteError);
    assert_eq!(map_error(-15), ErrorKind::BadContentEncoding);
    assert_eq!(map_error(-16), ErrorKind::WriteError);
    assert_eq!(map_error(-20), ErrorKind::BadContentEncoding);
    assert_eq!(map_error(-21), ErrorKind::OutOfMemory);
    assert_eq!(map_error(-30), ErrorKind::OutOfMemory);
    assert_eq!(map_error(-31), ErrorKind::WriteError);
}

/// The time is checked every 1 MiB made.
#[test]
fn a_transfer_out_of_time_stops_decoding() {
    let mut out = Collect {
        time_up: true,
        ..Collect::default()
    };
    let r = decoder().unwrap().decode(BR_3M, &mut out);
    assert_eq!(r, Err(ErrorKind::OperationTimedout));
    assert_eq!(out.made().len(), 64 * BUFFER);
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
    assert_eq!(version_number() >> 24, 1);
}
