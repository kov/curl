//! The trace formats, against the C tool's: the dumps are what
//! `curl --trace-ascii` and `curl --trace` wrote for the `.dat` files
//! beside these tests, read over `file://` (their libcurl lines left out).

use super::*;

fn dumped(data: &[u8], trace: Trace) -> String {
    let mut out = Vec::new();
    dump(&mut out, b"", DebugKind::DataIn, data, trace).unwrap();
    String::from_utf8(out).unwrap()
}

/// CR LF ends a line wherever it falls: inside a line, just past its
/// width, at its end, and twice in a row.
#[test]
fn dumps_ascii_as_c() {
    assert_eq!(
        dumped(include_bytes!("ascii.dat"), Trace::Ascii),
        include_str!("ascii.c-trace")
    );
}

/// Every byte value, sixteen to a line, the last line padded.
#[test]
fn dumps_binary_as_c() {
    assert_eq!(
        dumped(include_bytes!("binary.dat"), Trace::Binary),
        include_str!("binary.c-trace")
    );
}

#[test]
fn dumps_text_and_titles() {
    let mut out = Vec::new();
    dump(&mut out, b"T ", DebugKind::Text, b"hello\n", Trace::Ascii).unwrap();
    dump(
        &mut out,
        b"T ",
        DebugKind::HeaderOut,
        b"a\r\n",
        Trace::Ascii,
    )
    .unwrap();
    dump(&mut out, b"", DebugKind::SslDataOut, b"", Trace::Binary).unwrap();
    assert_eq!(
        String::from_utf8(out).unwrap(),
        "T * hello\nT => Send header, 3 bytes (0x3)\n0000: a\n=> Send SSL data, 0 bytes (0x0)\n"
    );
}

fn state() -> State {
    State {
        kind: Trace::Plain,
        time: false,
        sink: Sink::Stderr,
        mid_line: false,
        noted_data: false,
        scratch: Vec::new(),
    }
}

/// `--verbose`: every header line marked, a line split over two entries
/// marked once, data noted once until something else comes.
#[test]
fn writes_plain_lines_as_c() {
    let mut s = state();
    let mut out = Vec::new();
    let mut entry = |s: &mut State, kind, data: &[u8], stamp: &[u8]| {
        plain(s, &mut out, stamp, kind, data, false).unwrap();
    };
    entry(
        &mut s,
        DebugKind::HeaderOut,
        b"GET / HTTP/1.1\r\nHost: x\r\n\r\n",
        b"",
    );
    entry(&mut s, DebugKind::HeaderOut, b"PART", b"");
    entry(&mut s, DebugKind::HeaderOut, b"IAL\r\n", b"");
    entry(&mut s, DebugKind::HeaderIn, b"HTTP/1.1 200 OK\r\n", b"S ");
    entry(&mut s, DebugKind::DataIn, b"12345", b"");
    entry(&mut s, DebugKind::DataIn, b"678", b"");
    entry(&mut s, DebugKind::Text, b"note\n", b"");
    entry(&mut s, DebugKind::DataOut, b"9", b"");
    entry(&mut s, DebugKind::HeaderOut, b"", b"");
    entry(&mut s, DebugKind::DataOut, b"9", b"");
    assert_eq!(
        String::from_utf8(out).unwrap(),
        "> GET / HTTP/1.1\r\n> Host: x\r\n> \r\n> PARTIAL\r\nS < HTTP/1.1 200 OK\r\n\
         { [5 bytes data]\n* note\n} [1 bytes data]\n} [1 bytes data]\n"
    );
}

/// Data is not noted when it shows on the terminal the trace goes to.
#[test]
fn notes_no_data_shown_on_the_terminal() {
    let mut s = state();
    let mut out = Vec::new();
    plain(&mut s, &mut out, b"", DebugKind::DataIn, b"12345", true).unwrap();
    assert!(out.is_empty());
    s.sink = Sink::File {
        name: b"t\0".to_vec(),
        file: Some(tempfile()),
    };
    plain(&mut s, &mut out, b"", DebugKind::DataIn, b"12345", true).unwrap();
    assert_eq!(out, b"{ [5 bytes data]\n");
}

fn tempfile() -> File {
    let path = std::env::temp_dir().join(format!("curl-tool-trace-{}", std::process::id()));
    let file = File::create(&path).unwrap();
    std::fs::remove_file(&path).unwrap();
    file
}

/// `HH:MM:SS.uuuuuu `.
#[test]
fn stamps_the_time_of_day() {
    let stamp = String::from_utf8(timestamp().bytes().to_vec()).unwrap();
    assert_eq!(stamp.len(), 16, "{stamp:?}");
    let b = stamp.as_bytes();
    assert_eq!(
        (b[2], b[5], b[8], b[15]),
        (b':', b':', b'.', b' '),
        "{stamp:?}"
    );
}
