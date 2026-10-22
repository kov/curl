//! A response's head as it arrives (`lib/http.c`'s `http_parse_headers`
//! and `http_rw_hd`): lines assembled over any split of the input, folded
//! lines joined, the status line read, and the bytes counted against the
//! limits, one line at a time.

use std::fmt;

use curl_alloc::{OutOfMemory, TryVec as _};

use super::fields::{self, BadLine, MAX_HEADERS};
use super::framing::{Asked, Framing, FramingError, Meta, Notes, Sending};
use crate::error::ErrorKind;

/// The most one assembled line may be, the byte C's buffer keeps for
/// itself taken off (`CURL_MAX_HTTP_HEADER`).
const MAX_LINE: usize = 100 * 1024 - 1;

pub(crate) use crate::report::ResponseVersion as HttpVersion;

/// What the status line said.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Status {
    pub(crate) version: HttpVersion,
    /// Any three digits.
    pub(crate) code: u16,
}

/// What the request and its connection tell the parser.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Exchange {
    /// The version the request was sent in.
    pub(crate) sent: HttpVersion,
    /// The connection carried a response before this one.
    pub(crate) reused: bool,
    /// A response that is no HTTP may be HTTP/0.9 (`CURLOPT_HTTP09_ALLOWED`).
    pub(crate) allow_09: bool,
    /// What the request asks of the body's framing.
    pub(crate) asked: Asked,
}

/// One line of the head, to be delivered whole, then `then` to be raised:
/// the line counts against the limits only once the handlers have it.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Line<'a> {
    pub(crate) bytes: &'a [u8],
    pub(crate) kind: LineKind,
    /// What C says of the line before it delivers it.
    pub(crate) notes: Notes,
    /// A failure C reports before it delivers the line, and raises after
    /// (`http_on_response`, which writes the head's last line on its way
    /// out).
    pub(crate) early: Result<(), HeadError>,
    /// A failure C finds after it delivered the line.
    pub(crate) then: Result<(), HeadError>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum LineKind {
    /// The status line, read.
    Status(Status),
    /// A header line, verified.
    Header,
    /// The blank line ending a response's head; an interim one (1xx) is
    /// followed by another response.
    End { interim: bool },
}

/// What a feed produced.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum HeadEvent<'a> {
    Line(Line<'a>),
    /// No HTTP: these bytes and all that follow are an HTTP/0.9 body.
    Http09(&'a [u8]),
}

/// Why a head is refused, each as C says it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum HeadError {
    /// A line longer than C's line buffer, which C fails silently.
    LineTooLong,
    InvalidStatusLine,
    Http09NotAllowed,
    BadSubversion,
    UnknownVersion,
    VersionMismatch {
        sent: u8,
        got: u8,
    },
    BadLine(BadLine),
    TooLarge {
        bytes: u64,
        max: u64,
    },
    BadCode,
    /// What a header says of the body is refused.
    Framing(FramingError),
    OutOfMemory,
}

impl HeadError {
    pub(crate) fn kind(&self) -> ErrorKind {
        match self {
            HeadError::LineTooLong => ErrorKind::TooLarge,
            HeadError::InvalidStatusLine
            | HeadError::VersionMismatch { .. }
            | HeadError::BadLine(_) => ErrorKind::WeirdServerReply,
            HeadError::Http09NotAllowed
            | HeadError::BadSubversion
            | HeadError::UnknownVersion
            | HeadError::BadCode => ErrorKind::UnsupportedProtocol,
            HeadError::TooLarge { .. } => ErrorKind::RecvError,
            HeadError::Framing(FramingError::BadLength | FramingError::MultipleLocations) => {
                ErrorKind::WeirdServerReply
            }
            HeadError::Framing(FramingError::Returned(_)) => ErrorKind::HttpReturnedError,
            HeadError::Framing(FramingError::FileTooLarge) => ErrorKind::FilesizeExceeded,
            HeadError::Framing(FramingError::CannotResume) => ErrorKind::RangeError,
            HeadError::Framing(
                FramingError::Unsolicited(_)
                | FramingError::ListedAfterChunked(_)
                | FramingError::TooManyCodings
                | FramingError::ChunkedNotLast,
            ) => ErrorKind::BadContentEncoding,
            HeadError::Framing(FramingError::OutOfMemory) | HeadError::OutOfMemory => {
                ErrorKind::OutOfMemory
            }
        }
    }

    /// Whether C says why (`failf`); the others fail with no text.
    pub(crate) fn says(&self) -> bool {
        !matches!(
            self,
            HeadError::LineTooLong
                | HeadError::OutOfMemory
                | HeadError::Framing(FramingError::OutOfMemory)
        )
    }
}

impl fmt::Display for HeadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            HeadError::LineTooLong | HeadError::OutOfMemory => Ok(()),
            HeadError::Framing(ref e) => e.fmt(f),
            HeadError::InvalidStatusLine => f.write_str("Invalid status line"),
            HeadError::Http09NotAllowed => f.write_str("Received HTTP/0.9 when not allowed"),
            HeadError::BadSubversion => f.write_str("Unsupported HTTP/1 subversion in response"),
            HeadError::UnknownVersion => f.write_str("Unsupported HTTP version in response"),
            HeadError::VersionMismatch { sent, got } => {
                write!(f, "Version mismatch (from HTTP/{sent} to HTTP/{got})")
            }
            HeadError::BadLine(bad) => bad.fmt(f),
            HeadError::TooLarge { bytes, max } => {
                write!(f, "Too large response headers: {bytes} > {max}")
            }
            HeadError::BadCode => f.write_str("Unsupported response code in HTTP response"),
        }
    }
}

impl From<OutOfMemory> for HeadError {
    fn from(_: OutOfMemory) -> HeadError {
        HeadError::OutOfMemory
    }
}

/// Where the parser is in a request's responses.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Phase {
    /// Reading a head.
    Head,
    /// The final head ended, or the response is HTTP/0.9: what follows is
    /// body.
    Done,
}

/// A request's response heads, fed the bytes as they arrive.
#[derive(Debug)]
pub(crate) struct HeadParser {
    exchange: Exchange,
    phase: Phase,
    /// The line being assembled, or the one last given out (`headerb`).
    line: Vec<u8>,
    /// `line` was given out, and goes at the next feed.
    given: bool,
    /// A complete header line waits to see whether the next byte folds
    /// onto it.
    maybe_folded: bool,
    /// The blanks a fold leaves are to be passed over, then one space put.
    unfolding: bool,
    /// Lines of the current head given out (C's `headerline`): 1 is the
    /// status line.
    lines: u32,
    /// The current head's status, once read.
    status: Option<Status>,
    /// A status line was read for this request, an interim one included.
    version_seen: bool,
    /// One of them said HTTP/1.0.
    http10: bool,
    /// The version the last response said.
    last_version: Option<HttpVersion>,
    /// Head bytes of this request's responses (C's `allheadercount`).
    request_bytes: u64,
    /// Of those, the interim heads' up to the last that ended (C's
    /// `deductheadercount`, which a final head resets to no effect: its
    /// own bytes count).
    interim_bytes: u64,
    /// What the heads said so far.
    meta: Meta,
    /// The body's framing, once the final head ended.
    framing: Option<Framing>,
}

impl HeadParser {
    pub(crate) fn new(exchange: Exchange) -> HeadParser {
        HeadParser {
            exchange,
            phase: Phase::Head,
            line: Vec::new(),
            given: false,
            maybe_folded: false,
            unfolding: false,
            lines: 0,
            status: None,
            version_seen: false,
            http10: false,
            last_version: None,
            request_bytes: 0,
            interim_bytes: 0,
            meta: Meta::default(),
            framing: None,
        }
    }

    /// What the heads said so far.
    pub(crate) fn meta(&self) -> &Meta {
        &self.meta
    }

    pub(crate) fn meta_mut(&mut self) -> &mut Meta {
        &mut self.meta
    }

    /// The final head's status, once it ended.
    pub(crate) fn status(&self) -> Option<Status> {
        self.status.filter(|_| self.phase == Phase::Done)
    }

    /// A response to the request said HTTP/1.0.
    pub(crate) fn saw_http10(&self) -> bool {
        self.http10
    }

    /// The version the last response said, if one came.
    pub(crate) fn last_version(&self) -> Option<HttpVersion> {
        self.last_version
    }

    /// How the body is framed, once the final head ended.
    pub(crate) fn framing(&self) -> Option<Framing> {
        self.framing
    }

    /// Whether the final head has ended: what follows is body.
    #[cfg_attr(not(test), expect(dead_code, reason = "the driver reads framing"))]
    pub(crate) fn is_done(&self) -> bool {
        self.phase == Phase::Done
    }

    /// Head bytes of this request's responses, each line counted once
    /// delivered.
    pub(crate) fn request_bytes(&self) -> u64 {
        self.request_bytes
    }

    /// Bytes read and not given out: a line not ended, or one held to see
    /// whether the next continues it (`state.headerb` at the end).
    pub(crate) fn held(&self) -> &[u8] {
        if self.given { &[] } else { &self.line }
    }

    /// Count `held`, delivered at the end, against the limits.
    pub(crate) fn count_held(
        &mut self,
        len: u64,
        transfer_bytes: &mut u64,
    ) -> Result<(), HeadError> {
        self.count(len, transfer_bytes)
    }

    /// Whether the server sent nothing that counts: no head but interim
    /// ones, and no `body` bytes (`Curl_http_done`'s "Empty reply from
    /// server").
    pub(crate) fn got_nothing(&self, body: u64) -> bool {
        body + self.request_bytes - self.interim_bytes == 0
    }

    /// Read from `input`; `transfer_bytes` counts head bytes over every
    /// request of the transfer (C's `info.header_size`). Gives how much of
    /// `input` was used and what it made, if anything: feed the rest
    /// again until the head is done.
    pub(crate) fn feed<'s>(
        &'s mut self,
        mut input: &[u8],
        transfer_bytes: &mut u64,
        sending: Sending,
    ) -> Result<(usize, Option<HeadEvent<'s>>), HeadError> {
        if self.given {
            self.given = false;
            self.line.clear();
        }
        if self.phase == Phase::Done {
            return Ok((0, None));
        }
        let mut used = 0;
        if self.maybe_folded && !input.is_empty() {
            self.maybe_folded = false;
            if is_blank(input[0]) {
                self.unfold();
            } else {
                // The waiting line was whole.
                return self.line_out(transfer_bytes, sending).map(|e| (0, Some(e)));
            }
        }
        while !input.is_empty() {
            if self.unfolding {
                let blanks = input.iter().take_while(|&&b| is_blank(b)).count();
                input = &input[blanks..];
                used += blanks;
                if input.is_empty() {
                    break;
                }
                self.push(b" ")?;
                self.unfolding = false;
            }
            let Some(newline) = input.iter().position(|&b| b == b'\n') else {
                self.push(input)?;
                used += input.len();
                if self.lines == 0 && self.looks(&self.line) == Looks::No {
                    return self.not_http().map(|e| (used, Some(e)));
                }
                break;
            };
            self.push(&input[..=newline])?;
            input = &input[newline + 1..];
            used += newline + 1;
            if self.lines == 0 {
                if self.looks(&self.line) == Looks::No {
                    return self.not_http().map(|e| (used, Some(e)));
                }
            } else if !self.line.is_empty() && !is_newline(self.line[0]) {
                match input.first() {
                    Some(&b) if is_blank(b) => {
                        self.unfold();
                        continue;
                    }
                    Some(_) => {}
                    None => {
                        self.maybe_folded = true;
                        return Ok((used, None));
                    }
                }
            }
            return self
                .line_out(transfer_bytes, sending)
                .map(|e| (used, Some(e)));
        }
        Ok((used, None))
    }

    fn push(&mut self, bytes: &[u8]) -> Result<(), HeadError> {
        if self.line.len() + bytes.len() > MAX_LINE {
            return Err(HeadError::LineTooLong);
        }
        Ok(self.line.try_extend_from_slice(bytes)?)
    }

    /// The next line continues this one: its line end and trailing
    /// blanks go, and one space joins them (`Curl_http_to_fold`).
    fn unfold(&mut self) {
        if self.line.last() == Some(&b'\n') {
            self.line.pop();
        }
        if self.line.last() == Some(&b'\r') {
            self.line.pop();
        }
        while self.line.last().is_some_and(|&b| is_blank(b)) {
            self.line.pop();
        }
        self.unfolding = true;
    }

    /// Whether the start of a first line can be a status line
    /// (`checkhttpprefix`).
    fn looks(&self, line: &[u8]) -> Looks {
        let n = line.len().min(5);
        if !line[..n].eq_ignore_ascii_case(&b"HTTP/"[..n]) {
            Looks::No
        } else if line.len() >= 5 {
            Looks::Yes
        } else {
            Looks::Maybe
        }
    }

    /// The first line is no HTTP: HTTP/0.9, where that can be.
    fn not_http(&mut self) -> Result<HeadEvent<'_>, HeadError> {
        if self.version_seen || self.exchange.reused {
            return Err(HeadError::InvalidStatusLine);
        }
        if !self.exchange.allow_09 {
            return Err(HeadError::Http09NotAllowed);
        }
        self.phase = Phase::Done;
        self.given = true;
        Ok(HeadEvent::Http09(&self.line))
    }

    /// Give out the complete line in `line` (`http_rw_hd`).
    fn line_out(
        &mut self,
        transfer_bytes: &mut u64,
        sending: Sending,
    ) -> Result<HeadEvent<'_>, HeadError> {
        self.given = true;
        let mut note = Notes::default();
        // An error said before the line is delivered, and raised after.
        let mut first = Ok(());
        let mut bad_code = false;
        let kind = if is_newline(self.line[0]) {
            let status = self.status.expect("a head ends after its status line");
            // Below 100 is no response C knows (`http_on_response`).
            bad_code = status.code < 100;
            let interim = (100..200).contains(&status.code);
            if interim {
                self.lines = 0;
                self.status = None;
            } else {
                self.phase = Phase::Done;
                if !bad_code {
                    let (said, framing) = self.meta.decide(status, &self.exchange.asked, sending);
                    note = said;
                    match framing {
                        Ok(framing) => self.framing = Some(framing),
                        Err(e) => first = Err(HeadError::Framing(e)),
                    }
                }
            }
            LineKind::End { interim }
        } else {
            self.lines += 1;
            let kind = if self.lines == 1 {
                let status = read_status(&self.line)?;
                if status.version.major() != self.exchange.sent.major() {
                    return Err(HeadError::VersionMismatch {
                        sent: self.exchange.sent.major(),
                        got: status.version.major(),
                    });
                }
                self.status = Some(status);
                self.version_seen = true;
                self.http10 |= status.version == HttpVersion::Http10;
                self.last_version = Some(status.version);
                note = Notes::one(self.meta.on_status(status));
                LineKind::Status(status)
            } else {
                LineKind::Header
            };
            fields::verify_line(&self.line, self.lines).map_err(HeadError::BadLine)?;
            if kind == LineKind::Header {
                let status = self.status.expect("headers follow their status line");
                let following = self.meta.follow().is_some();
                note = Notes::one(
                    self.meta
                        .on_header(&self.line, status, &self.exchange.asked)
                        .map_err(HeadError::Framing)?,
                );
                // A location to follow (`http_header_l`).
                if !following && self.meta.follow().is_some() {
                    self.meta.perhaps_rewind(sending, &mut note);
                }
            }
            kind
        };
        let counted = self.count(self.line.len() as u64, transfer_bytes);
        if kind == (LineKind::End { interim: true }) {
            self.interim_bytes = self.request_bytes;
        }
        // Below 200, C writes the line before it looks at the code.
        let then = counted.and_then(|()| (!bad_code).then_some(()).ok_or(HeadError::BadCode));
        Ok(HeadEvent::Line(Line {
            bytes: &self.line,
            kind,
            notes: note,
            early: first,
            then,
        }))
    }

    fn count(&mut self, len: u64, transfer_bytes: &mut u64) -> Result<(), HeadError> {
        count_head(len, &mut self.request_bytes, transfer_bytes)
    }

    /// Lines of the final head given out, its status line among them.
    pub(crate) fn lines(&self) -> u32 {
        self.lines
    }
}

/// Count a delivered head line, or trailer, against the limits
/// (`Curl_bump_headersize`): 300 KiB for a request's heads, twenty times
/// that for the transfer's.
pub(crate) fn count_head(
    len: u64,
    request_bytes: &mut u64,
    transfer_bytes: &mut u64,
) -> Result<(), HeadError> {
    let max = MAX_HEADERS as u64;
    if len >= max {
        return Err(HeadError::TooLarge {
            bytes: *request_bytes + len,
            max,
        });
    }
    *transfer_bytes += len;
    *request_bytes += len;
    if *request_bytes > max {
        Err(HeadError::TooLarge {
            bytes: *request_bytes,
            max,
        })
    } else if *transfer_bytes > max * 20 {
        Err(HeadError::TooLarge {
            bytes: *transfer_bytes,
            max: max * 20,
        })
    } else {
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Looks {
    No,
    Maybe,
    Yes,
}

/// Read a status line: `HTTP/1.0` or `HTTP/1.1` and three digits,
/// whatever follows them, or `HTTP/2` or `HTTP/3`, three digits and a
/// blank; blanks may lead. Any other line that got this far starts with
/// `HTTP/` in some case, which makes it a 200 in HTTP/1.0 (C's
/// `HTTP200ALIASES` check, which always knows `HTTP/`).
fn read_status(line: &[u8]) -> Result<Status, HeadError> {
    const ALIAS: Status = Status {
        version: HttpVersion::Http10,
        code: 200,
    };
    let start = line.iter().take_while(|&&b| is_blank(b)).count();
    let p = &line[start..];
    let digits = |d: &[u8]| -> Option<u16> {
        let d = d.get(..3)?;
        d.iter().all(u8::is_ascii_digit).then(|| {
            d.iter()
                .fold(0, |code, &digit| code * 10 + u16::from(digit - b'0'))
        })
    };
    let Some(after) = p.strip_prefix(b"HTTP/") else {
        return Ok(ALIAS);
    };
    match after.first() {
        Some(b'1') => {
            let version = match after.get(1..4) {
                Some([b'.', b'0', b]) if is_blank(*b) => HttpVersion::Http10,
                Some([b'.', b'1', b]) if is_blank(*b) => HttpVersion::Http11,
                _ => return Err(HeadError::BadSubversion),
            };
            let code = digits(&after[4..]).ok_or(HeadError::BadSubversion)?;
            Ok(Status { version, code })
        }
        Some(&major @ (b'2' | b'3')) => {
            let version = if major == b'2' {
                HttpVersion::Http2
            } else {
                HttpVersion::Http3
            };
            if !after.get(1).is_some_and(|&b| is_blank(b)) {
                return Ok(ALIAS);
            }
            match digits(&after[2..]) {
                Some(code) if after.get(5).is_some_and(|&b| is_blank(b)) => {
                    Ok(Status { version, code })
                }
                _ => Ok(ALIAS),
            }
        }
        _ => Err(HeadError::UnknownVersion),
    }
}

fn is_blank(b: u8) -> bool {
    b == b' ' || b == b'\t'
}

fn is_newline(b: u8) -> bool {
    b == b'\r' || b == b'\n'
}

#[cfg(test)]
mod tests;
