//! A tunnel through an HTTP proxy (`lib/cf-h1-proxy.c`): the `CONNECT`
//! request (`http_proxy_create_CONNECT`), and the proxy's answer read a
//! byte at a time, so that nothing past it is taken from the tunnel
//! (`recv_CONNECT_resp`, `single_header`, `on_resp_header`).
//!
//! It does no I/O and says nothing: the answer's lines are given out one
//! by one, for the transfer to trace and deliver, then applied.

use std::fmt;

use curl_alloc::{OutOfMemory, TryVec as _};

use super::chunked::{ChunkDecoder, ChunkError};
use super::fields::{self, BadLine};
use super::framing::value_of;
use super::request::{Trusted, UserHeaders};

/// The longest line of an answer (`DYN_PROXY_CONNECT_HEADERS`).
const MAX_LINE: usize = 16384;

/// What a `CONNECT` request says.
#[derive(Debug)]
pub(crate) struct ConnectRequest<'a> {
    /// The host and port the tunnel goes to, an IPv6 address in brackets.
    pub(crate) authority: &'a [u8],
    /// Sent as HTTP/1.0 (`CURLPROXY_HTTP_1_0`).
    pub(crate) http10: bool,
    /// The method and what follows its name in `Proxy-Authorization`.
    pub(crate) proxy_authorization: Option<(&'static str, &'a [u8])>,
    /// None, or an empty one, sends none.
    pub(crate) user_agent: Option<&'a [u8]>,
    /// The application's lines for the proxy, which replace the
    /// library's Host, User-Agent and Proxy-Connection and follow them.
    pub(crate) headers: &'a UserHeaders,
    /// Its Authorization and Cookie may go (`Curl_auth_allowed_to_host`).
    pub(crate) trusted: Option<Trusted>,
}

impl ConnectRequest<'_> {
    /// The request's head, as C's `Curl_h1_req_write_head` writes it.
    pub(crate) fn render(&self, out: &mut Vec<u8>) -> Result<(), OutOfMemory> {
        let version: &[u8] = if self.http10 { b"1.0" } else { b"1.1" };
        let mut line = |parts: &[&[u8]]| -> Result<(), OutOfMemory> {
            for part in parts {
                out.try_extend_from_slice(part)?;
            }
            out.try_extend_from_slice(b"\r\n")
        };
        let theirs = |name: &[u8]| self.headers.replaces(name);
        line(&[b"CONNECT ", self.authority, b" HTTP/", version])?;
        if !theirs(b"Host") {
            line(&[b"Host: ", self.authority])?;
        }
        if let Some((method, value)) = self.proxy_authorization {
            line(&[b"Proxy-Authorization: ", method.as_bytes(), b" ", value])?;
        }
        if let Some(ua) = self
            .user_agent
            .filter(|ua| !ua.is_empty() && !theirs(b"User-Agent"))
        {
            line(&[b"User-Agent: ", ua])?;
        }
        if !theirs(b"Proxy-Connection") {
            line(&[b"Proxy-Connection: Keep-Alive"])?;
        }
        for (name, value) in self.headers.for_connect(self.trusted) {
            line(&[name, b": ", value])?;
        }
        line(&[])
    }
}

/// The proxy's answer to a `CONNECT`, as it is read.
#[derive(Debug)]
pub(crate) struct Answer {
    /// The line being read, or the last one given out.
    line: Vec<u8>,
    /// The line in `line` is whole, given out and not applied yet.
    whole: bool,
    /// The line in `line` was applied, and goes as the next is read.
    applied: bool,
    /// Lines given out, the status line first (`headerlines`).
    lines: u32,
    code: Option<u16>,
    /// `Content-Length` of a body not wanted (`cl`).
    length: u64,
    chunked: bool,
    /// The proxy closes the connection after the answer
    /// (`close_connection`).
    close: bool,
    /// A line ended; the next byte says whether it goes on (`maybe_folded`).
    folded: bool,
    /// The line goes on: the blanks leading its next part are skipped
    /// (`leading_unfold`).
    unfold: bool,
    body: Body,
    /// A dropped chunked body was read to its end.
    chunks_read: bool,
}

/// Where the answer is (C's `keepon`).
#[derive(Debug)]
enum Body {
    /// Its head is read.
    Head,
    /// The head ended, its blank line given out and not applied yet.
    HeadEnded,
    /// A body of `0` more bytes is read and dropped.
    Ignore(u64),
    /// A chunked body is read and dropped.
    Chunked(ChunkDecoder),
    Done,
}

/// What reading the answer came to.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Read {
    /// A line is whole, to be traced and delivered, then applied.
    Line,
    /// The input is used up.
    More,
    /// The answer ended.
    Done,
}

/// What a line said.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Applied {
    Nothing,
    /// A 407's `Proxy-Authenticate:`, to be read for the proxy.
    Challenge,
    /// Something to say (`infof`).
    Note(Note),
    /// The head ended: `end_head` decides what of the body is read.
    End,
}

/// What reading an answer says.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Note {
    IgnoringLength(u16),
    IgnoringEncoding(u16),
    /// A 407's body of so many bytes is dropped.
    IgnoreBytes(u64),
    IgnoreChunked,
}

impl fmt::Display for Note {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Note::IgnoringLength(code) => {
                write!(f, "Ignoring Content-Length in CONNECT {code:03} response")
            }
            Note::IgnoringEncoding(code) => {
                write!(
                    f,
                    "Ignoring Transfer-Encoding in CONNECT {code:03} response"
                )
            }
            Note::IgnoreBytes(n) => write!(f, "Ignore {n} bytes of response-body"),
            Note::IgnoreChunked => f.write_str("Ignore chunked response-body"),
        }
    }
}

/// Why an answer is refused.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum AnswerError {
    OutOfMemory,
    /// A line longer than C's buffer: "CONNECT response too large".
    TooLarge,
    BadLine(BadLine),
    /// The first line is no `HTTP/1.x NNN`.
    BadStatus,
    /// The head ended at its first line.
    NoHead,
    LengthIn1xx(u16),
    EncodingIn1xx(u16),
    BadLength,
    /// The dropped body's chunks are malformed.
    BadChunks(ChunkError),
}

impl AnswerError {
    /// What C says of it, if anything (`failf`).
    pub(crate) fn said(self) -> Option<Said> {
        match self {
            AnswerError::OutOfMemory | AnswerError::NoHead => None,
            // The decoder's reason alone: no writer sums it up here.
            AnswerError::BadChunks(ref bad) if bad.reason().is_none() => None,
            _ => Some(Said(self)),
        }
    }
}

/// An error, as C says it.
pub(crate) struct Said(AnswerError);

impl fmt::Display for Said {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.0 {
            AnswerError::TooLarge => f.write_str("CONNECT response too large"),
            AnswerError::BadLine(bad) => bad.fmt(f),
            AnswerError::BadChunks(bad) => match bad.reason() {
                Some(reason) => reason.fmt(f),
                None => Ok(()),
            },
            AnswerError::BadStatus => f.write_str("Invalid response header"),
            AnswerError::LengthIn1xx(code) => {
                write!(f, "Invalid Content-Length: in {code:03} response")
            }
            AnswerError::EncodingIn1xx(code) => {
                write!(f, "Invalid Transfer-Encoding: in {code:03} response")
            }
            AnswerError::BadLength => f.write_str("Unsupported Content-Length value"),
            AnswerError::OutOfMemory | AnswerError::NoHead => Ok(()),
        }
    }
}

impl From<OutOfMemory> for AnswerError {
    fn from(_: OutOfMemory) -> AnswerError {
        AnswerError::OutOfMemory
    }
}

impl Answer {
    pub(crate) fn new() -> Answer {
        Answer {
            line: Vec::new(),
            whole: false,
            applied: false,
            lines: 0,
            code: None,
            length: 0,
            chunked: false,
            close: false,
            folded: false,
            unfold: false,
            body: Body::Head,
            chunks_read: false,
        }
    }

    /// The status the proxy answered with, once its line is applied.
    pub(crate) fn code(&self) -> Option<u16> {
        self.code
    }

    /// The proxy closes the connection after it.
    pub(crate) fn closes(&self) -> bool {
        self.close
    }

    /// The line given out, until the next is read.
    pub(crate) fn line(&self) -> &[u8] {
        assert!(self.whole || self.applied, "a line is given out");
        &self.line
    }

    /// Read from `input`: how much was used, and what that came to.
    pub(crate) fn read(&mut self, input: &[u8]) -> Result<(usize, Read), AnswerError> {
        assert!(!self.whole, "the line given out is applied first");
        if self.applied {
            self.applied = false;
            self.line.clear();
        }
        let mut used = 0;
        while used < input.len() {
            match &mut self.body {
                Body::Head => {}
                Body::HeadEnded => unreachable!("applied first"),
                Body::Done => return Ok((used, Read::Done)),
                Body::Ignore(left) => {
                    let rest = &input[used..];
                    let n = rest.len().min(usize::try_from(*left).unwrap_or(usize::MAX));
                    *left -= n as u64;
                    used += n;
                    if *left == 0 {
                        self.body = Body::Done;
                        return Ok((used, Read::Done));
                    }
                    continue;
                }
                Body::Chunked(decoder) => {
                    // Read no further than the body's end.
                    let mut counted = 0;
                    let (n, _) = decoder
                        .feed(&input[used..], &mut counted)
                        .map_err(AnswerError::BadChunks)?;
                    used += n;
                    if decoder.is_done() {
                        self.body = Body::Done;
                        self.chunks_read = true;
                        return Ok((used, Read::Done));
                    }
                    // Short of its end the decoder takes all it is given;
                    // what it might leave is offered again.
                    break;
                }
            }
            let byte = input[used];
            if self.folded {
                self.folded = false;
                if byte == b' ' || byte == b'\t' {
                    self.fold();
                    self.unfold = true;
                } else {
                    // The line is whole; the byte waits for the next.
                    self.whole = true;
                    return Ok((used, Read::Line));
                }
            }
            used += 1;
            if self.unfold {
                if byte == b' ' || byte == b'\t' {
                    continue;
                }
                self.push(b' ')?;
                self.unfold = false;
            }
            self.push(byte)?;
            if byte != b'\n' {
                continue;
            }
            if matches!(self.line[0], b'\r' | b'\n') {
                // The blank line ends the head at once.
                self.whole = true;
                return Ok((used, Read::Line));
            }
            self.folded = true;
        }
        Ok((used, Read::More))
    }

    /// The connection closed: a line read whole is given out, else the
    /// answer ends where it is.
    pub(crate) fn closed(&mut self) -> Read {
        if self.folded {
            self.folded = false;
            self.whole = true;
            return Read::Line;
        }
        Read::Done
    }

    fn push(&mut self, byte: u8) -> Result<(), AnswerError> {
        if self.line.len() >= MAX_LINE - 1 {
            return Err(AnswerError::TooLarge);
        }
        self.line.try_push(byte)?;
        Ok(())
    }

    /// The line goes on: its end and trailing blanks go (`Curl_http_to_fold`).
    fn fold(&mut self) {
        if self.line.last() == Some(&b'\n') {
            self.line.pop();
        }
        if self.line.last() == Some(&b'\r') {
            self.line.pop();
        }
        while self.line.last().is_some_and(|b| matches!(b, b' ' | b'\t')) {
            self.line.pop();
        }
    }

    /// Whether the line given out may be delivered: C checks it as a
    /// response's line before any, whose number is not yet counted
    /// (`Curl_verify_header`).
    pub(crate) fn verify(&self) -> Result<(), AnswerError> {
        assert!(self.whole, "a line is given out");
        fields::verify_line(&self.line, 0).map_err(AnswerError::BadLine)
    }

    /// The line given out, delivered, is taken in (`single_header`): the
    /// status line, a header, or the blank line ending the head.
    pub(crate) fn apply(&mut self) -> Result<Applied, AnswerError> {
        assert!(self.whole, "a line is given out");
        self.whole = false;
        self.applied = true;
        self.lines += 1;
        let applied = if matches!(self.line[0], b'\r' | b'\n') {
            if self.lines == 1 {
                return Err(AnswerError::NoHead);
            }
            self.body = Body::HeadEnded;
            Applied::End
        } else if self.lines == 1 {
            self.code = Some(status(&self.line).ok_or(AnswerError::BadStatus)?);
            Applied::Nothing
        } else {
            self.header()?
        };
        Ok(applied)
    }

    /// What a header says (`on_resp_header`).
    fn header(&mut self) -> Result<Applied, AnswerError> {
        let code = self.code.expect("the status line came first");
        let line = &self.line[..];
        if code == 407 && value_of(line, b"Proxy-authenticate:").is_some() {
            return Ok(Applied::Challenge);
        }
        if let Some(rest) = value_of(line, b"Content-Length:") {
            if code < 300 {
                if code < 200 {
                    return Err(AnswerError::LengthIn1xx(code));
                }
                return Ok(Applied::Note(Note::IgnoringLength(code)));
            }
            self.length = number(rest).ok_or(AnswerError::BadLength)?;
        } else if fields::header_says(line, b"Connection:", b"close") {
            self.close = true;
        } else if value_of(line, b"Transfer-Encoding:").is_some() {
            if code < 300 {
                if code < 200 {
                    return Err(AnswerError::EncodingIn1xx(code));
                }
                return Ok(Applied::Note(Note::IgnoringEncoding(code)));
            }
            if fields::header_says(line, b"Transfer-Encoding:", b"chunked") {
                self.chunked = true;
            }
        } else if fields::header_says(line, b"Proxy-Connection:", b"close") {
            self.close = true;
        }
        Ok(Applied::Nothing)
    }

    /// The head ended: a 407's body is read and dropped, to keep the
    /// connection, unless authenticating went wrong; one with no length
    /// leaves the connection to end it, and is not read. Chunks are
    /// decoded where both are said, though the note names the length,
    /// as C has it.
    pub(crate) fn end_head(&mut self, auth_problem: bool) -> Option<Note> {
        assert!(matches!(self.body, Body::HeadEnded), "the head ended");
        self.body = Body::Done;
        if self.code != Some(407) || auth_problem {
            return None;
        }
        if self.chunked {
            self.body = Body::Chunked(ChunkDecoder::new(true, 0, 0));
        } else if self.length > 0 {
            self.body = Body::Ignore(self.length);
        }
        if self.length > 0 {
            Some(Note::IgnoreBytes(self.length))
        } else if self.chunked {
            Some(Note::IgnoreChunked)
        } else {
            None
        }
    }

    /// Whether the head ended and nothing of a body is left to read.
    pub(crate) fn done(&self) -> bool {
        matches!(self.body, Body::Done)
    }

    /// A dropped chunked body was read to its end.
    pub(crate) fn chunks_read(&self) -> bool {
        self.chunks_read
    }
}

/// `HTTP/1.0 NNN` or `HTTP/1.1 NNN`, not followed by a digit
/// (`on_resp_status`).
fn status(line: &[u8]) -> Option<u16> {
    let digit = |i: usize| {
        line.get(i)
            .filter(|b| b.is_ascii_digit())
            .map(|b| u16::from(b - b'0'))
    };
    if !line.starts_with(b"HTTP/1.")
        || !matches!(line.get(7), Some(b'0' | b'1'))
        || line.get(8) != Some(&b' ')
    {
        return None;
    }
    let code = digit(9)? * 100 + digit(10)? * 10 + digit(11)?;
    digit(12).is_none().then_some(code)
}

/// A number after blanks (`curlx_str_numblanks`): what follows it is not
/// looked at.
fn number(v: &[u8]) -> Option<u64> {
    let v = &v[v.iter().take_while(|&&b| b == b' ' || b == b'\t').count()..];
    let digits = v.iter().take_while(|b| b.is_ascii_digit()).count();
    if digits == 0 {
        return None;
    }
    let mut n: u64 = 0;
    for &b in &v[..digits] {
        n = n.checked_mul(10)?.checked_add(u64::from(b - b'0'))?;
    }
    // C's `curl_off_t`.
    (n <= i64::MAX as u64).then_some(n)
}

#[cfg(test)]
mod tests;
