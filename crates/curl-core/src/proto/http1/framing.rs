//! What a response's head says about its body and its connection, applied
//! as each line arrives with C's gates (`http_statusline`,
//! `http_header_c`, `http_header_t`, `Curl_build_unencoding_stack`), and
//! the body's framing folded from it at the head's end (`http_on_response`,
//! `http_size`).

use std::fmt;
use std::num::NonZeroU64;

use curl_alloc::{OutOfMemory, TryVec as _};

use super::fields;
use super::response::{HttpVersion, Status};

/// The most transfer codings a response may stack (`MAX_ENCODE_STACK`).
const MAX_CODINGS: u8 = 5;

/// What the request asks of the response's framing.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Asked {
    /// No body is wanted (`CURLOPT_NOBODY`, a HEAD).
    pub(crate) head: bool,
    /// `Content-Length` is not read (`CURLOPT_IGNORE_CONTENT_LENGTH`).
    pub(crate) ignore_length: bool,
    pub(crate) max_filesize: Option<NonZeroU64>,
    /// Transfer codings other than chunked are decoded
    /// (`CURLOPT_TRANSFER_ENCODING`).
    pub(crate) decode_codings: bool,
    /// Transfer codings are passed on undecoded
    /// (`CURLOPT_HTTP_TRANSFER_DECODING` off).
    pub(crate) raw_codings: bool,
}

/// How the body after a final head ends.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Framing {
    /// There is none to read.
    None,
    Length(u64),
    Chunked,
    /// When the connection closes.
    UntilClose,
}

/// Something C says of a head as it reads it (`infof`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Note {
    Http10Close,
    Http10KeepAlive,
    LengthOverflow,
    AssumeClose,
}

impl fmt::Display for Note {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Note::Http10Close => "HTTP 1.0, assume close after body",
            Note::Http10KeepAlive => "HTTP/1.0 connection set to keep alive",
            Note::LengthOverflow => "Overflow Content-Length: value",
            Note::AssumeClose => "no chunk, no close, no size. Assume close to signal end",
        })
    }
}

/// Why what a head says is refused.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum FramingError {
    BadLength,
    FileTooLarge,
    /// A transfer coding the request did not ask to decode.
    Unsolicited(Vec<u8>),
    ListedAfterChunked(Vec<u8>),
    TooManyCodings,
    ChunkedNotLast,
    OutOfMemory,
}

/// Bytes shown as text, what is not UTF-8 as U+FFFD, without
/// allocating.
pub(crate) struct Lossy<'b>(pub(crate) &'b [u8]);

impl fmt::Display for Lossy<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for chunk in self.0.utf8_chunks() {
            f.write_str(chunk.valid())?;
            if !chunk.invalid().is_empty() {
                f.write_str("\u{FFFD}")?;
            }
        }
        Ok(())
    }
}

impl fmt::Display for FramingError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = |n| Lossy(n);
        match self {
            FramingError::BadLength => f.write_str("Invalid Content-Length: value"),
            FramingError::FileTooLarge => f.write_str("Maximum file size exceeded"),
            FramingError::Unsolicited(n) => {
                write!(f, "Unsolicited Transfer-Encoding ({}) found", name(n))
            }
            FramingError::ListedAfterChunked(n) => write!(
                f,
                "A Transfer-Encoding ({}) was listed after chunked",
                name(n)
            ),
            FramingError::TooManyCodings => write!(
                f,
                "Reject response exceeding limit of {MAX_CODINGS} transfer encodings"
            ),
            FramingError::ChunkedNotLast => {
                f.write_str("Reject response due to 'chunked' not being the last Transfer-Encoding")
            }
            FramingError::OutOfMemory => Ok(()),
        }
    }
}

impl From<OutOfMemory> for FramingError {
    fn from(_: OutOfMemory) -> FramingError {
        FramingError::OutOfMemory
    }
}

/// What a request's response heads said so far.
#[derive(Debug, Default)]
pub(crate) struct Meta {
    /// The current response may carry no body (1xx, 204, 304).
    bodyless: bool,
    /// The body's size, from `Content-Length` or the status.
    size: Option<u64>,
    chunked: bool,
    /// Transfer decoders stacked, chunked among them.
    codings: u8,
    /// A transfer coding other than chunked makes `Content-Length` void.
    length_void: bool,
    /// The connection closes after the response.
    close: bool,
    content_type: Option<Vec<u8>>,
    /// The response announced trailers.
    trailer: bool,
}

impl Meta {
    /// A status line was read.
    pub(crate) fn on_status(&mut self, status: Status) -> Option<Note> {
        self.bodyless = (100..200).contains(&status.code);
        if matches!(status.code, 204 | 304) {
            self.size = Some(0);
            self.bodyless = true;
        }
        // HTTP/1.0 closes unless it says otherwise.
        (status.version == HttpVersion::Http10).then(|| {
            self.close = true;
            Note::Http10Close
        })
    }

    /// A header `line` of the response whose status is `status` arrived.
    pub(crate) fn on_header(
        &mut self,
        line: &[u8],
        status: Status,
        asked: &Asked,
    ) -> Result<Option<Note>, FramingError> {
        if !self.bodyless
            && !asked.ignore_length
            && !self.length_void
            && let Some(v) = value_of(line, b"Content-Length:")
        {
            return self.length(v, asked);
        }
        if let Some(v) = value_of(line, b"Content-Type:") {
            let v = fields::header_value(line).unwrap_or(&v[..0]);
            if !v.is_empty() {
                let mut copy = Vec::new();
                copy.try_extend_from_slice(v)?;
                self.content_type = Some(copy);
            }
            return Ok(None);
        }
        let h1 = matches!(status.version, HttpVersion::Http10 | HttpVersion::Http11);
        if h1 && says(line, b"Connection:", b"close") {
            self.close = true;
            return Ok(None);
        }
        if status.version == HttpVersion::Http10 && says(line, b"Connection:", b"keep-alive") {
            self.close = false;
            return Ok(Some(Note::Http10KeepAlive));
        }
        // A HEAD's or a 304's codings would be the body's it does not have
        // (RFC 9112, section 6.1); a 304 is bodyless.
        if !self.bodyless
            && !asked.head
            && let Some(v) = value_of(line, b"Transfer-Encoding:")
        {
            self.codings(v, asked)?;
            if !self.chunked {
                // Only the close ends a body coded otherwise.
                self.close = true;
                self.length_void = true;
            }
            return Ok(None);
        }
        if value_of(line, b"Trailer:").is_some() {
            self.trailer = true;
        }
        Ok(None)
    }

    /// `Content-Length`: a number, or a list of the same number, or the
    /// same number again.
    fn length(&mut self, mut v: &[u8], asked: &Asked) -> Result<Option<Note>, FramingError> {
        loop {
            v = skip_blanks(v);
            let digits = v.iter().take_while(|b| b.is_ascii_digit()).count();
            if digits == 0 {
                return Err(FramingError::BadLength);
            }
            let Some(n) = std::str::from_utf8(&v[..digits])
                .ok()
                .and_then(|d| d.parse::<i64>().ok())
            else {
                // Too large to be a size.
                if asked.max_filesize.is_some() {
                    return Err(FramingError::FileTooLarge);
                }
                self.close = true;
                return Ok(Some(Note::LengthOverflow));
            };
            let n = n as u64;
            if self.size.is_some_and(|s| s != n) {
                return Err(FramingError::BadLength);
            }
            self.size = Some(n);
            v = skip_blanks(&v[digits..]);
            match v.first() {
                Some(b',') => v = &v[1..],
                Some(b'\r' | b'\n') => return Ok(None),
                _ => return Err(FramingError::BadLength),
            }
        }
    }

    /// `Transfer-Encoding`'s codings, stacked as decoders.
    fn codings(&mut self, list: &[u8], asked: &Asked) -> Result<(), FramingError> {
        let mut chunked_here = false;
        for name in coding_names(list) {
            let is_chunked = name.eq_ignore_ascii_case(b"chunked");
            if !asked.decode_codings && !is_chunked {
                if asked.raw_codings {
                    return Ok(());
                }
                if chunked_here {
                    return Err(FramingError::ListedAfterChunked(copy(name)?));
                }
                if name.eq_ignore_ascii_case(b"identity") {
                    continue;
                }
                return Err(FramingError::Unsolicited(copy(name)?));
            }
            if self.codings >= MAX_CODINGS {
                return Err(FramingError::TooManyCodings);
            }
            if !is_chunked && self.chunked {
                return Err(FramingError::ChunkedNotLast);
            }
            // A second chunked is ignored.
            if !(is_chunked && self.chunked) {
                self.codings += 1;
                self.chunked |= is_chunked;
            }
            chunked_here |= is_chunked;
        }
        Ok(())
    }

    /// The final head ended: how its body is framed, as the request asked.
    pub(crate) fn decide(
        &mut self,
        status: Status,
        asked: &Asked,
    ) -> (Option<Note>, Result<Framing, FramingError>) {
        let mut note = None;
        if self.size.is_none()
            && !self.chunked
            && !self.close
            && status.version == HttpVersion::Http11
            && !asked.head
        {
            // RFC 2616, section 4.4, point 5.
            self.close = true;
            note = Some(Note::AssumeClose);
        }
        if self.length_void || self.chunked {
            self.size = None;
        } else if let (Some(size), Some(max)) = (self.size, asked.max_filesize)
            && size > max.get()
        {
            return (note, Err(FramingError::FileTooLarge));
        }
        let framing = if asked.head {
            Framing::None
        } else if self.chunked {
            Framing::Chunked
        } else {
            match self.size {
                Some(0) => Framing::None,
                Some(n) => Framing::Length(n),
                None => Framing::UntilClose,
            }
        };
        (note, Ok(framing))
    }

    /// The connection closes after the response.
    pub(crate) fn close(&self) -> bool {
        self.close
    }

    #[cfg_attr(
        not(test),
        expect(dead_code, reason = "CURLINFO_CONTENT_TYPE is not reported yet")
    )]
    pub(crate) fn content_type(&self) -> Option<&[u8]> {
        self.content_type.as_deref()
    }

    /// The response announced trailers.
    #[cfg_attr(
        not(test),
        expect(dead_code, reason = "only a multiplexed response waits for them")
    )]
    pub(crate) fn trailer(&self) -> bool {
        self.trailer
    }

    /// The body's size as the head gives it.
    pub(crate) fn size(&self) -> Option<u64> {
        self.size
    }
}

/// The rest of `line` after its name `name`, which includes the colon
/// (C's `HD_VAL`).
fn value_of<'l>(line: &'l [u8], name: &[u8]) -> Option<&'l [u8]> {
    (line.len() >= name.len() && line[..name.len()].eq_ignore_ascii_case(name))
        .then(|| &line[name.len()..])
}

/// Whether `line` is the header `name` and lists `token` (C's
/// `HD_IS_AND_SAYS`).
fn says(line: &[u8], name: &[u8], token: &[u8]) -> bool {
    line.len() > name.len() + token.len()
        && value_of(line, name).is_some()
        && fields::header_says(line, name, token)
}

fn skip_blanks(v: &[u8]) -> &[u8] {
    let n = v.iter().take_while(|&&b| b == b' ' || b == b'\t').count();
    &v[n..]
}

/// The names in a list of codings: between commas, leading blanks gone,
/// up to the last byte above a space.
fn coding_names(list: &[u8]) -> impl Iterator<Item = &[u8]> {
    let list = list
        .iter()
        .position(|&b| b == 0)
        .map_or(list, |end| &list[..end]);
    list.split(|&b| b == b',').filter_map(|part| {
        let part = skip_blanks(part);
        let len = part.iter().rposition(|&b| b > b' ').map_or(0, |p| p + 1);
        (len > 0).then(|| &part[..len])
    })
}

fn copy(name: &[u8]) -> Result<Vec<u8>, FramingError> {
    let mut out = Vec::new();
    out.try_extend_from_slice(name)?;
    Ok(out)
}
