//! A chunked body (`lib/http_chunks.c`): chunk sizes in hex, their data,
//! and the trailers after the last, fed the bytes as they arrive.

use std::fmt;

use curl_alloc::{OutOfMemory, TryVec as _};

use super::fields::{self, BadLine};
use super::framing::Lossy;
use super::response::{self, HeadError};
use crate::error::ErrorKind;

/// The most hex digits a chunk's size may have (`CHUNK_MAXNUM_LEN`).
const MAX_HEX: usize = 17;

/// The most one trailer line may be, the byte C's buffer keeps for itself
/// taken off (`DYN_H1_TRAILER`).
const MAX_TRAILER: usize = 4096 - 1;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum State {
    /// Reading a chunk's size.
    Hex,
    /// Past the size: everything up to the line's LF, extensions
    /// included, is passed over.
    Lf,
    /// `left` bytes of the chunk's data to come.
    Data,
    /// After the data: CRs, then the LF.
    PostLf,
    /// After the last chunk: a trailer line, or the end.
    Trailer,
    /// A trailer line's CR came: its LF.
    TrailerCr,
    /// A trailer line ended: another, or the end's CR.
    TrailerPostCr,
    /// The end's LF.
    Stop,
    Done,
}

/// What a feed produced.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum ChunkEvent<'a> {
    /// Body bytes, from the input.
    Data(&'a [u8]),
    /// A trailer line, verified, to be delivered as a header, then `then`
    /// raised.
    Trailer {
        line: &'a [u8],
        then: Result<(), ChunkError>,
    },
    /// The body ended; what is left of the input is no part of it.
    Done,
}

/// Why a chunked body is refused.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum ChunkError {
    TooLongHex,
    NotHex(u8),
    BadSize([u8; MAX_HEX], usize),
    Malformed,
    BadTrailer(BadLine),
    TrailerTooLong,
    TrailerLimit(HeadError),
    /// The input ended before the body did.
    Outstanding,
    OutOfMemory,
}

impl ChunkError {
    pub(crate) fn kind(&self) -> ErrorKind {
        match self {
            ChunkError::TooLongHex
            | ChunkError::NotHex(_)
            | ChunkError::BadSize(..)
            | ChunkError::Malformed
            | ChunkError::TrailerLimit(_) => ErrorKind::RecvError,
            ChunkError::BadTrailer(_) => ErrorKind::WeirdServerReply,
            ChunkError::TrailerTooLong => ErrorKind::TooLarge,
            ChunkError::Outstanding => ErrorKind::PartialFile,
            ChunkError::OutOfMemory => ErrorKind::OutOfMemory,
        }
    }

    /// What C says first, where it says two things: the reason, before
    /// the chunked writer's summary.
    pub(crate) fn reason(&self) -> Option<Reason<'_>> {
        match self {
            ChunkError::TooLongHex
            | ChunkError::NotHex(_)
            | ChunkError::BadSize(..)
            | ChunkError::BadTrailer(_)
            | ChunkError::TrailerLimit(_) => Some(Reason(self)),
            ChunkError::Malformed
            | ChunkError::TrailerTooLong
            | ChunkError::Outstanding
            | ChunkError::OutOfMemory => None,
        }
    }
}

/// The reason of a `ChunkError` that has one.
#[derive(Debug)]
pub(crate) struct Reason<'e>(&'e ChunkError);

impl fmt::Display for Reason<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.0 {
            ChunkError::TooLongHex => write!(f, "chunk hex-length longer than {MAX_HEX}"),
            ChunkError::NotHex(b) => write!(f, "chunk hex-length char not a hex digit: 0x{b:x}"),
            ChunkError::BadSize(hex, len) => {
                write!(f, "invalid chunk size: '{}'", Lossy(&hex[..*len]))
            }
            ChunkError::BadTrailer(bad) => bad.fmt(f),
            ChunkError::TrailerLimit(e) => e.fmt(f),
            other => unreachable!("{other:?} has no reason"),
        }
    }
}

impl fmt::Display for ChunkError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let code = match self {
            ChunkError::Outstanding => {
                return f.write_str("transfer closed with outstanding read data remaining");
            }
            ChunkError::OutOfMemory => return Ok(()),
            ChunkError::TooLongHex => "Too long hexadecimal number",
            ChunkError::NotHex(_) | ChunkError::BadSize(..) => {
                "Illegal or missing hexadecimal sequence"
            }
            ChunkError::Malformed | ChunkError::BadTrailer(_) => "Malformed encoding found",
            // C's buffer refuses the byte as too large, which the decoder
            // reports as it reports an allocation failing.
            ChunkError::TrailerTooLong => "Out of memory",
            ChunkError::TrailerLimit(_) => "trailers exceeded header limit",
        };
        write!(f, "{code} in chunked-encoding")
    }
}

impl From<OutOfMemory> for ChunkError {
    fn from(_: OutOfMemory) -> ChunkError {
        ChunkError::OutOfMemory
    }
}

/// A chunked body, after the final head of a response.
#[derive(Debug)]
pub(crate) struct ChunkDecoder {
    state: State,
    hex: [u8; MAX_HEX],
    hex_len: usize,
    left: u64,
    trailer: Vec<u8>,
    /// `trailer` was given out, and goes at the next feed.
    given: bool,
    /// The bytes are passed on as they came (`CURLOPT_HTTP_TRANSFER_DECODING`
    /// off): no data or trailers are given out, though the body is still
    /// read to its end.
    raw: bool,
    /// Lines in the final head, which decides whether a blank-led trailer
    /// continues one.
    head_lines: u32,
    /// The request's head bytes so far, trailers counting.
    request_bytes: u64,
}

impl ChunkDecoder {
    pub(crate) fn new(raw: bool, head_lines: u32, request_bytes: u64) -> ChunkDecoder {
        ChunkDecoder {
            state: State::Hex,
            hex: [0; MAX_HEX],
            hex_len: 0,
            left: 0,
            trailer: Vec::new(),
            given: false,
            raw,
            head_lines,
            request_bytes,
        }
    }

    pub(crate) fn is_done(&self) -> bool {
        self.state == State::Done
    }

    /// The input ended: the body must have.
    pub(crate) fn finish(&self) -> Result<(), ChunkError> {
        if self.is_done() {
            Ok(())
        } else {
            Err(ChunkError::Outstanding)
        }
    }

    /// Read from `input`, as `HeadParser::feed` does: how much was used
    /// and what it made, if anything.
    pub(crate) fn feed<'i>(
        &'i mut self,
        input: &'i [u8],
        transfer_bytes: &mut u64,
    ) -> Result<(usize, Option<ChunkEvent<'i>>), ChunkError> {
        if self.given {
            self.given = false;
            self.trailer.clear();
        }
        let mut used = 0;
        while used < input.len() {
            let b = input[used];
            match self.state {
                State::Hex => {
                    if b.is_ascii_hexdigit() {
                        if self.hex_len >= MAX_HEX {
                            return Err(ChunkError::TooLongHex);
                        }
                        self.hex[self.hex_len] = b;
                        self.hex_len += 1;
                        used += 1;
                    } else {
                        if self.hex_len == 0 {
                            return Err(ChunkError::NotHex(b));
                        }
                        let digits = &self.hex[..self.hex_len];
                        self.left = std::str::from_utf8(digits)
                            .ok()
                            .and_then(|d| i64::from_str_radix(d, 16).ok())
                            .ok_or(ChunkError::BadSize(self.hex, self.hex_len))?
                            as u64;
                        self.state = State::Lf;
                    }
                }
                State::Lf => {
                    if b == b'\n' {
                        self.state = if self.left == 0 {
                            State::Trailer
                        } else {
                            State::Data
                        };
                    }
                    used += 1;
                }
                State::Data => {
                    let rest = &input[used..];
                    let piece =
                        usize::try_from(self.left).map_or(rest.len(), |l| l.min(rest.len()));
                    self.left -= piece as u64;
                    if self.left == 0 {
                        self.state = State::PostLf;
                    }
                    let data = &rest[..piece];
                    used += piece;
                    if !self.raw {
                        return Ok((used, Some(ChunkEvent::Data(data))));
                    }
                }
                State::PostLf => {
                    if b == b'\n' {
                        self.state = State::Hex;
                        self.hex_len = 0;
                    } else if b != b'\r' {
                        return Err(ChunkError::Malformed);
                    }
                    used += 1;
                }
                State::Trailer => {
                    if b == b'\r' || b == b'\n' {
                        if self.trailer.is_empty() {
                            // No trailer: the end's CRLF.
                            self.state = State::TrailerPostCr;
                            continue;
                        }
                        if self.trailer.len() + 2 > MAX_TRAILER {
                            return Err(ChunkError::TrailerTooLong);
                        }
                        self.trailer.try_extend_from_slice(b"\r\n")?;
                        fields::verify_line(&self.trailer, self.head_lines)
                            .map_err(ChunkError::BadTrailer)?;
                        self.state = State::TrailerCr;
                        if b == b'\r' {
                            used += 1;
                        }
                        if self.raw {
                            self.trailer.clear();
                            continue;
                        }
                        self.given = true;
                        let len = self.trailer.len() as u64;
                        let then =
                            response::count_head(len, &mut self.request_bytes, transfer_bytes)
                                .map_err(ChunkError::TrailerLimit);
                        return Ok((
                            used,
                            Some(ChunkEvent::Trailer {
                                line: &self.trailer,
                                then,
                            }),
                        ));
                    }
                    if self.trailer.len() + 1 > MAX_TRAILER {
                        return Err(ChunkError::TrailerTooLong);
                    }
                    self.trailer.try_push(b)?;
                    used += 1;
                }
                State::TrailerCr => {
                    if b != b'\n' {
                        return Err(ChunkError::Malformed);
                    }
                    self.state = State::TrailerPostCr;
                    used += 1;
                }
                State::TrailerPostCr => {
                    if b != b'\r' && b != b'\n' {
                        // Another trailer line.
                        self.state = State::Trailer;
                        continue;
                    }
                    if b == b'\r' {
                        used += 1;
                    }
                    self.state = State::Stop;
                }
                State::Stop => {
                    if b != b'\n' {
                        return Err(ChunkError::Malformed);
                    }
                    self.state = State::Done;
                    return Ok((used + 1, Some(ChunkEvent::Done)));
                }
                State::Done => return Ok((used, None)),
            }
        }
        Ok((used, None))
    }
}

/// The largest chunk the encoder makes (`CURL_CHUNKED_MAXLEN`), and the
/// least body it asks for at once (`CURL_CHUNKED_MINLEN`).
const CHUNK_MAX: usize = 64 * 1024;
const CHUNK_MIN: usize = 1024;

/// The most a chunk's size line takes: eight hex digits and CRLF.
const SIZE_LINE: usize = 8 + 2;

/// The last chunk, empty, and the end of the trailers (`add_last_chunk`).
const LAST_CHUNK: &[u8] = b"0\r\n\r\n";

/// A body sent chunked (`cr_chunked`): each piece the body gives becomes a
/// chunk, and its end the last, empty one. It reads into its own buffer,
/// which the request's then takes from.
#[derive(Debug)]
pub(crate) struct ChunkEncoder {
    /// Framed bytes not yet taken are `buf[start..end]`; a piece of body
    /// is read at `SIZE_LINE`, its size line put right before it.
    buf: Vec<u8>,
    start: usize,
    end: usize,
    /// The body has ended (`read_eos`), and its last chunk has been taken
    /// as well (`eos`).
    read_eos: bool,
    eos: bool,
}

impl ChunkEncoder {
    pub(crate) fn new() -> Result<ChunkEncoder, OutOfMemory> {
        const LEN: usize = SIZE_LINE + CHUNK_MAX + 2 + LAST_CHUNK.len();
        let mut buf = Vec::new();
        buf.try_extend_from_slice(&[0; LEN])?;
        Ok(ChunkEncoder {
            buf,
            start: 0,
            end: 0,
            read_eos: false,
            eos: false,
        })
    }

    /// Whether the body should be read for `room` bytes of the request's
    /// buffer, and where to: what is framed is taken first, and the read
    /// is a decent chunk's worth however little room there is, or what
    /// will fit framed (`add_chunk`).
    pub(crate) fn wants(&mut self, room: usize) -> Option<&mut [u8]> {
        if self.read_eos || self.start < self.end {
            return None;
        }
        let room = room.min(CHUNK_MAX);
        let n = if room < CHUNK_MIN {
            CHUNK_MIN
        } else {
            room - (SIZE_LINE + 2)
        };
        Some(&mut self.buf[SIZE_LINE..SIZE_LINE + n])
    }

    /// The body gave `n` bytes where `wants` said, and ended if `end`
    /// gives its trailer lines, each with its CRLF: frame them, and the
    /// last chunk after them (`add_chunk`, `add_last_chunk`).
    pub(crate) fn got(&mut self, n: usize, end: Option<&[u8]>) -> Result<(), OutOfMemory> {
        assert!(
            self.start == self.end && !self.read_eos,
            "read only when wanted"
        );
        self.start = SIZE_LINE;
        self.end = SIZE_LINE;
        if n > 0 {
            let mut hex = [0u8; SIZE_LINE];
            let mut cursor = std::io::Cursor::new(&mut hex[..]);
            std::io::Write::write_fmt(&mut cursor, format_args!("{n:x}\r\n"))
                .expect("a chunk's size line fits");
            let len = cursor.position() as usize;
            let line = &hex[..len];
            self.start = SIZE_LINE - line.len();
            self.buf[self.start..SIZE_LINE].copy_from_slice(line);
            self.end = SIZE_LINE + n;
            self.buf[self.end..self.end + 2].copy_from_slice(b"\r\n");
            self.end += 2;
        }
        if let Some(trailers) = end {
            self.read_eos = true;
            // Within the room kept for it unless there are trailers.
            self.buf.truncate(self.end);
            self.buf.try_extend_from_slice(b"0\r\n")?;
            self.buf.try_extend_from_slice(trailers)?;
            self.buf.try_extend_from_slice(b"\r\n")?;
            self.end = self.buf.len();
        }
        Ok(())
    }

    /// Framed bytes into `dest`: how many, and whether the last chunk is
    /// all taken (`cr_chunked_read`).
    pub(crate) fn take(&mut self, dest: &mut [u8]) -> (usize, bool) {
        let n = (self.end - self.start).min(dest.len());
        dest[..n].copy_from_slice(&self.buf[self.start..self.start + n]);
        self.start += n;
        if self.read_eos && self.start == self.end {
            self.eos = true;
        }
        (n, self.eos)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::http1::fixture;
    use crate::proto::http1::framing::{Asked, Framing};
    use crate::proto::http1::response::{Exchange, HeadEvent, HeadParser, HttpVersion};

    /// What a chunked response came to.
    #[derive(Debug, Default, PartialEq, Eq)]
    struct Got {
        body: Vec<u8>,
        trailers: Vec<Vec<u8>>,
        done: bool,
        /// Input left in the feed that ended the body.
        leftover: usize,
        error: Option<ChunkError>,
    }

    /// Read `reply`'s head, then its chunked body, fed in `chunks`; raw,
    /// each piece of the body's input is delivered as it came, as C's
    /// chunked writer does.
    fn read(chunks: &[&[u8]], raw: bool) -> Got {
        let exchange = Exchange {
            sent: HttpVersion::Http11,
            reused: false,
            allow_09: false,
            asked: Asked {
                head: false,
                ignore_length: false,
                max_filesize: None,
                decode_codings: false,
                raw_codings: raw,
                fail_on_error: false,
                resume_from: None,
                follow: false,
                auth: Default::default(),
            },
        };
        let mut head = HeadParser::new(exchange);
        let mut body: Option<ChunkDecoder> = None;
        let mut got = Got::default();
        let mut transfer = 0;
        for chunk in chunks {
            let mut input = *chunk;
            while !input.is_empty() {
                let Some(decoder) = body.as_mut() else {
                    let (used, event) = head.feed(input, &mut transfer).unwrap();
                    input = &input[used..];
                    if let Some(HeadEvent::Line(line)) = event {
                        line.early.and(line.then).unwrap();
                    }
                    if head.is_done() {
                        assert_eq!(head.framing(), Some(Framing::Chunked));
                        body = Some(ChunkDecoder::new(raw, head.lines(), head.request_bytes()));
                    }
                    continue;
                };
                if raw && !got.done {
                    got.body.extend_from_slice(input);
                }
                // As C's writer is called once per piece, its raw copy
                // made, and the decoder runs over it.
                let mut piece = input;
                input = &[];
                while !piece.is_empty() && !decoder.is_done() {
                    let (used, event) = match decoder.feed(piece, &mut transfer) {
                        Ok(fed) => fed,
                        Err(e) => {
                            got.error = Some(e);
                            return got;
                        }
                    };
                    match event {
                        Some(ChunkEvent::Data(d)) => got.body.extend_from_slice(d),
                        Some(ChunkEvent::Trailer { line, then }) => {
                            got.trailers.push(line.to_vec());
                            then.unwrap();
                        }
                        Some(ChunkEvent::Done) => {
                            got.done = true;
                            got.leftover = piece.len() - used;
                        }
                        None => assert!(used > 0, "no progress"),
                    }
                    piece = &piece[used..];
                }
            }
        }
        if let Some(decoder) = &body
            && let Err(e) = decoder.finish()
        {
            got.error = Some(e);
        }
        got
    }

    /// `read` of `reply` whole, which every split into two and a byte at
    /// a time must give alike, raw output aside.
    fn chunked(reply: &[u8], raw: bool) -> Got {
        let whole = read(&[reply], raw);
        for at in 0..=reply.len() {
            let (a, b) = reply.split_at(at);
            let split = read(&[a, b], raw);
            assert_eq!(
                (&split.body, &split.trailers, split.done, &split.error),
                (&whole.body, &whole.trailers, whole.done, &whole.error),
                "split at {at}"
            );
        }
        let bytes: Vec<&[u8]> = reply.chunks(1).collect();
        let one = read(&bytes, raw);
        assert_eq!(
            (&one.body, &one.error),
            (&whole.body, &whole.error),
            "byte by byte"
        );
        whole
    }

    fn abc() -> Vec<u8> {
        [&[b'a'; 64][..], &[b'b'; 48], &[b'c'; 32], b"\n"].concat()
    }

    /// Chunks with an extension and a size not on a line of its own
    /// (test 34).
    #[test]
    fn chunks_are_joined_into_the_body() {
        let got = chunked(&fixture::reply(34), false);
        assert_eq!((got.body, got.done, got.error), (abc(), true, None));
        assert_eq!(got.trailers, Vec::<Vec<u8>>::new());
    }

    /// Trailers are given out as header lines ending in CRLF, with LF
    /// alone too (tests 266, 1417, 1116, 1482, 1483, 1493).
    #[test]
    fn trailers_are_header_lines() {
        let trailer = b"chunky-trailer: header data\r\n".to_vec();
        for test in [266, 1417] {
            let got = chunked(&fixture::reply(test), false);
            assert_eq!(
                (got.body, got.trailers, got.done, got.error),
                (abc(), vec![trailer.clone()], true, None),
                "test {test}"
            );
        }
        let two = vec![trailer.clone(), b"another-header: yes\r\n".to_vec()];
        for test in [1116, 1482, 1483, 1493] {
            let got = chunked(&fixture::reply(test), false);
            assert_eq!((&got.trailers, got.done), (&two, true), "test {test}");
        }
    }

    /// Bad chunks, a body cut short, and a bad trailer (tests 36, 207,
    /// 1416, 2106).
    #[test]
    fn bad_chunks_are_refused() {
        let got = chunked(&fixture::reply(36), false);
        assert_eq!(
            (&got.body[..], &got.error),
            (&b"a\n"[..], &Some(ChunkError::NotHex(b'I')))
        );
        let e = got.error.unwrap();
        assert_eq!(
            e.reason().unwrap().to_string(),
            "chunk hex-length char not a hex digit: 0x49"
        );
        assert_eq!(
            (e.to_string(), e.kind()),
            (
                "Illegal or missing hexadecimal sequence in chunked-encoding".into(),
                ErrorKind::RecvError
            )
        );
        let got = chunked(&fixture::reply(207), false);
        let e = got.error.unwrap();
        assert_eq!(got.body.len(), 65);
        assert_eq!(
            (e.to_string(), e.kind()),
            (
                "transfer closed with outstanding read data remaining".into(),
                ErrorKind::PartialFile
            )
        );
        let got = chunked(&fixture::reply(1416), false);
        let e = got.error.unwrap();
        assert_eq!(
            e.reason().unwrap().to_string(),
            "invalid chunk size: '12345678123456789'"
        );
        assert_eq!(e.kind(), ErrorKind::RecvError);
        let got = chunked(&fixture::reply(2106), false);
        let e = got.error.unwrap();
        assert_eq!(e, ChunkError::BadTrailer(BadLine::Nul));
        assert_eq!(
            (e.to_string(), e.kind()),
            (
                "Malformed encoding found in chunked-encoding".into(),
                ErrorKind::WeirdServerReply
            )
        );
    }

    /// The chunk grammar's corners.
    #[test]
    fn the_grammar_s_corners() {
        let head = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n";
        let body = |chunks: &[u8]| chunked(&[&head[..], chunks].concat(), false);
        let got = body(b"3 ; x=\"y\"\r\nabc\r\r\n0;e\r\n\r\nafter");
        assert_eq!(
            (got.body, got.done, got.leftover),
            (b"abc".to_vec(), true, 5)
        );
        assert_eq!(body(b"3\r\nabcX").error, Some(ChunkError::Malformed));
        assert_eq!(body(b"0\r\n\r\r").error, Some(ChunkError::Malformed));
        assert_eq!(body(b"0\r\nA: b\rx").error, Some(ChunkError::Malformed));
        assert_eq!(body(b"0\nA: b\n\n").trailers, vec![b"A: b\r\n".to_vec()]);
        assert_eq!(
            body(b"0\r\nno colon\r\n\r\n").error,
            Some(ChunkError::BadTrailer(BadLine::NoColon))
        );
        // A blank-led trailer passes the colon check as a fold only after
        // a head of three lines or more, as C counts them; the header
        // store refuses it then, which C reports as a failed delivery.
        assert_eq!(
            body(b"0\r\n folded\r\n\r\n").error,
            Some(ChunkError::BadTrailer(BadLine::NoColon))
        );
        let longer =
            b"HTTP/1.1 200 OK\r\nA: b\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n folded\r\n\r\n";
        assert_eq!(
            chunked(longer, false).trailers,
            vec![b" folded\r\n".to_vec()]
        );
        let max = body(b"7fffffffffffffff\r\nab").error;
        assert_eq!(max, Some(ChunkError::Outstanding));
        assert_eq!(body(b"00000000000000001\r\na\r\n0\r\n\r\n").body, b"a");
        assert_eq!(
            body(b"000000000000000001\r\n").error,
            Some(ChunkError::TooLongHex)
        );
        assert_eq!(
            body(b"000000000000000001\r\n")
                .error
                .unwrap()
                .reason()
                .unwrap()
                .to_string(),
            "chunk hex-length longer than 17"
        );
    }

    /// A trailer line holds 4 KiB less the CRLF and the byte C's buffer
    /// keeps.
    #[test]
    fn a_trailer_is_at_most_4_kib() {
        let reply = |value: usize| {
            let mut r = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n0\r\nA:".to_vec();
            r.resize(r.len() + value, b'a');
            r.extend_from_slice(b"\r\n\r\n");
            r
        };
        let fits = 4096 - 1 - 2 - 2;
        let got = read(&[&reply(fits)], false);
        assert_eq!((got.trailers[0].len(), got.error), (4095, None));
        let got = read(&[&reply(fits + 1)], false);
        let e = got.error.unwrap();
        assert_eq!(
            (e.to_string(), e.kind()),
            (
                "Out of memory in chunked-encoding".into(),
                ErrorKind::TooLarge
            )
        );
        // A line that never ends is refused at its 4096th byte, before
        // the input ends.
        let mut endless = reply(0);
        endless.truncate(endless.len() - 4);
        endless.resize(endless.len() + 4096 - 2, b'a');
        assert_eq!(
            read(&[&endless], false).error,
            Some(ChunkError::TrailerTooLong)
        );
        // One byte fewer is still a line that may end: the input ends
        // with it outstanding, not too long.
        endless.pop();
        assert_eq!(
            read(&[&endless], false).error,
            Some(ChunkError::Outstanding)
        );
    }

    /// Trailers count against the request's head limit.
    #[test]
    fn trailers_count_against_the_head_limit() {
        let mut d = ChunkDecoder::new(false, 2, 300 * 1024 - 5);
        let mut transfer = 0;
        let input = b"0\r\nA: bc\r\n\r\n";
        let (_, event) = d.feed(input, &mut transfer).unwrap();
        let Some(ChunkEvent::Trailer { line, then }) = event else {
            panic!("{event:?}");
        };
        assert_eq!(line, b"A: bc\r\n");
        let e = then.unwrap_err();
        assert_eq!(
            e.reason().unwrap().to_string(),
            "Too large response headers: 307202 > 307200"
        );
        assert_eq!(
            e.to_string(),
            "trailers exceeded header limit in chunked-encoding"
        );
    }

    /// Raw, the bytes go on as they came, and the body still ends where
    /// the chunks do (test 326).
    #[test]
    fn raw_chunks_go_on_as_they_came() {
        let got = read(&[&fixture::reply(326)], true);
        assert_eq!(
            (&got.body[..], got.trailers.len(), got.done),
            (
                &b"18\r\nline 1\n line 2\n  line 3\n\r\n0\r\n\r\n"[..],
                0,
                true
            )
        );
        let reply = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n0\r\nA: b\r\n\r\n";
        let got = read(&[reply], true);
        assert_eq!(
            (got.trailers.len(), got.done),
            (0, true),
            "not given out raw"
        );
    }

    /// Each piece of body is a chunk and its end the last; a small room
    /// still reads a decent chunk, taken over several calls, and a large
    /// one reads what fits framed.
    #[test]
    fn encodes_pieces_as_chunks() {
        let mut e = ChunkEncoder::new().unwrap();
        let room = e.wants(10).unwrap();
        assert_eq!(room.len(), CHUNK_MIN);
        room[..3].copy_from_slice(b"abc");
        e.got(3, None).unwrap();
        assert!(e.wants(10).is_none(), "framed bytes first");
        let mut dest = [0u8; 4];
        assert_eq!(e.take(&mut dest), (4, false));
        assert_eq!(&dest, b"3\r\na");
        let mut dest = [0u8; 10];
        assert_eq!(e.take(&mut dest), (4, false));
        assert_eq!(&dest[..4], b"bc\r\n");
        assert_eq!(e.wants(100_000).unwrap().len(), CHUNK_MAX - 12);
        e.got(0, Some(b"")).unwrap();
        assert!(e.wants(10).is_none(), "ended");
        assert_eq!(e.take(&mut dest), (5, true));
        assert_eq!(&dest[..5], b"0\r\n\r\n");
        let mut e = ChunkEncoder::new().unwrap();
        let room = e.wants(CHUNK_MAX).unwrap();
        room.fill(b'x');
        let n = room.len();
        e.got(n, Some(b"X: y\r\n")).unwrap();
        let mut all = vec![0u8; CHUNK_MAX + 100];
        let (took, eos) = e.take(&mut all);
        assert!(eos);
        assert_eq!(&all[..6], b"fff4\r\n");
        assert!(all[..took].ends_with(b"x\r\n0\r\nX: y\r\n\r\n"));
        assert_eq!(took, 6 + n + 2 + 11, "trailers after the last chunk");
    }
}
