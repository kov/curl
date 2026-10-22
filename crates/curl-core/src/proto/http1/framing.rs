//! What a response's head says about its body and its connection, applied
//! as each line arrives with C's gates (`http_statusline`,
//! `http_header_c`, `http_header_t`, `Curl_build_unencoding_stack`), and
//! the body's framing folded from it at the head's end (`http_on_response`,
//! `http_size`).

use std::fmt;
use std::num::NonZeroU64;
use std::time::Duration;

use curl_alloc::{OutOfMemory, TryVec as _};

use super::fields;
use super::response::{HttpVersion, Status};
use crate::date::{self, BadDate};
use crate::options::AuthMethods;
use crate::proto::http::auth::{AuthAct, AuthAsked, Heard, HeardNote, Offered};

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
    /// A code of 400 or more fails the response (`CURLOPT_FAILONERROR`).
    pub(crate) fail_on_error: bool,
    /// The offset a GET resumes at: a 416 does not fail it, and the
    /// response must start there.
    pub(crate) resume_from: Option<u64>,
    /// A redirect's `Location:` is followed (`CURLOPT_FOLLOWLOCATION`).
    pub(crate) follow: bool,
    /// What the request knows of authenticating, for a 401 to act on.
    pub(crate) auth: AuthAsked,
    /// The connection goes through an HTTP proxy, whose
    /// `Proxy-Connection` then says whether it stays open.
    pub(crate) http_proxy: bool,
    /// The request went to an HTTP proxy that sends it on, whose 407
    /// alone is the proxy's to read (`origin_is_proxy`): through a
    /// tunnel, or to a host reached without one, it is the origin's.
    pub(crate) forwarded: bool,
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
    /// None is read: the transfer ends at the head, and whatever follows
    /// it goes with the connection.
    Abandoned,
}

/// Something C says of a head as it reads it (`infof`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Note {
    Http10Close,
    Http10KeepAlive,
    ProxyKeepAlive,
    ProxyClose,
    LengthOverflow,
    AssumeClose,
    AlreadyDownloaded,
    SizeWhileIgnoring,
    IgnoringBody,
    /// A challenge asked again for the method the request used, or
    /// could not be read.
    AuthProblem(AuthMethods),
    /// A second Digest challenge, not read.
    DuplicateDigest,
    /// What a challenge line has C say, given out one by one by
    /// `Notes::iter`.
    Heard(Heard),
}

/// What C says of a line before it delivers it: at most two notes.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct Notes([Option<Note>; 2]);

impl Notes {
    pub(crate) fn one(note: Option<Note>) -> Notes {
        Notes([note, None])
    }

    fn push(&mut self, note: Note) {
        let free = self.0.iter_mut().find(|n| n.is_none());
        *free.expect("at most two notes to a line") = Some(note);
    }

    /// The notes, a challenge line's one by one.
    pub(crate) fn iter(&self) -> impl Iterator<Item = Note> + '_ {
        self.0.iter().flatten().flat_map(|&note| {
            let (one, heard) = match note {
                Note::Heard(heard) => (None, Some(heard)),
                note => (Some(note), None),
            };
            let heard = heard.into_iter().flat_map(Heard::notes).map(|n| match n {
                HeardNote::Problem(method) => Note::AuthProblem(method),
                HeardNote::DuplicateDigest => Note::DuplicateDigest,
            });
            one.into_iter().chain(heard)
        })
    }
}

impl fmt::Display for Note {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Note::Http10Close => "HTTP 1.0, assume close after body",
            Note::Http10KeepAlive => "HTTP/1.0 connection set to keep alive",
            Note::ProxyKeepAlive => "HTTP/1.0 proxy connection set to keep alive",
            Note::ProxyClose => "HTTP/1.1 proxy connection set close",
            Note::LengthOverflow => "Overflow Content-Length: value",
            Note::AssumeClose => "no chunk, no close, no size. Assume close to signal end",
            Note::AlreadyDownloaded => "The entire document is already downloaded",
            Note::SizeWhileIgnoring => "setting size while ignoring",
            Note::IgnoringBody => "Ignoring the response-body",
            Note::AuthProblem(method) => {
                return write!(f, "{} authentication problem, ignoring.", method.name());
            }
            Note::DuplicateDigest => "Ignoring duplicate digest auth header.",
            Note::Heard(_) => unreachable!("given out one by one by `Notes::iter`"),
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
    /// A second `Location` that says something else.
    MultipleLocations,
    /// The response's code is an error the request asked to fail on.
    Returned(u16),
    /// The response to a resumed GET starts elsewhere than asked.
    CannotResume,
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
            FramingError::MultipleLocations => f.write_str("Multiple Location headers"),
            FramingError::Returned(code) => {
                write!(f, "The requested URL returned error: {code}")
            }
            FramingError::CannotResume => {
                f.write_str("HTTP server does not seem to support byte ranges. Cannot resume.")
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

/// Whether a final response with `code` fails the request, once what it
/// led to in authenticating is known (`http_should_fail`).
fn should_fail(code: u16, asked: &Asked, auth: &AuthAct) -> bool {
    asked.fail_on_error
        && code >= 400
        && !(asked.resume_from.is_some() && code == 416)
        && auth.fails(code, &asked.auth)
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
    /// Where the response points (`req.location`).
    location: Option<Vec<u8>>,
    /// The location came with a redirect and is to be followed
    /// (`req.newurl`).
    follow: bool,
    /// The response announced trailers.
    trailer: bool,
    /// `Content-Range` starts at the offset the GET resumes at.
    content_range: bool,
    /// `Content-Range` with no start, on a success: the whole document
    /// comes, and the resume is off (`resume_from = 0`).
    whole: bool,
    /// The body is read and dropped: a 416 to a resumed GET
    /// (`ignorebody`).
    ignore_body: bool,
    /// What a 401's and a 407's challenges offered.
    challenges: Offered,
    /// What the final head led to in authenticating.
    auth: AuthAct,
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
        if value_of(line, b"Proxy-Connection:").is_some() {
            // C reads the field for nothing more (`http_header_p`).
            if !asked.http_proxy {
                return Ok(None);
            }
            return Ok(match status.version {
                HttpVersion::Http10 if says(line, b"Proxy-Connection:", b"keep-alive") => {
                    self.close = false;
                    Some(Note::ProxyKeepAlive)
                }
                HttpVersion::Http11 if says(line, b"Proxy-Connection:", b"close") => {
                    self.close = true;
                    Some(Note::ProxyClose)
                }
                _ => None,
            });
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
        if value_of(line, b"Location:").is_some() {
            // An empty one, or the same again, is passed over
            // (`http_header_l`).
            let v = fields::header_value(line).unwrap_or(&[]);
            if v.is_empty() || self.location.as_deref() == Some(v) {
                return Ok(None);
            }
            if self.location.is_some() {
                return Err(FramingError::MultipleLocations);
            }
            self.location = Some(copy(v)?);
            self.follow = asked.follow && (300..400).contains(&status.code);
            return Ok(None);
        }
        if !self.bodyless
            && let Some(v) = value_of(line, b"Content-Range:")
        {
            self.range(v, status, asked);
            return Ok(None);
        }
        if value_of(line, b"Trailer:").is_some() {
            self.trailer = true;
        }
        let challenge = match status.code {
            401 if value_of(line, b"WWW-Authenticate:").is_some() => {
                Some((&mut self.challenges.host, &asked.auth.host))
            }
            407 if asked.forwarded && value_of(line, b"Proxy-Authenticate:").is_some() => {
                Some((&mut self.challenges.proxy, &asked.auth.proxy))
            }
            _ => None,
        };
        if let Some((challenges, asked)) = challenge {
            let v = fields::header_value(line).unwrap_or(&[]);
            let heard = challenges.read(v, asked)?;
            return Ok((!heard.is_empty()).then_some(Note::Heard(heard)));
        }
        Ok(None)
    }

    /// `Content-Range`: `bytes N-`, `bytes: N-`, `N-`, or `*/total` for
    /// a range not satisfied. Only where it starts is read.
    fn range(&mut self, v: &[u8], status: Status, asked: &Asked) {
        let at = v
            .iter()
            .position(|&b| b.is_ascii_digit() || b == b'*')
            .unwrap_or(v.len());
        let v = &v[at..];
        let digits = v.iter().take_while(|b| b.is_ascii_digit()).count();
        if digits > 0 {
            let start = std::str::from_utf8(&v[..digits])
                .ok()
                .and_then(|d| d.parse::<i64>().ok());
            if let (Some(start), Some(from)) = (start, asked.resume_from)
                && start as u64 == from
            {
                self.content_range = true;
            }
        } else if status.code < 300 {
            self.whole = true;
        }
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
    ) -> (Notes, Result<Framing, FramingError>) {
        let mut note = Notes::default();
        if self.size.is_none()
            && !self.chunked
            && !self.close
            && status.version == HttpVersion::Http11
            && !asked.head
        {
            // RFC 2616, section 4.4, point 5.
            self.close = true;
            note.push(Note::AssumeClose);
        }
        self.auth = AuthAct::of(status.code, &self.challenges, &asked.auth);
        if should_fail(status.code, asked, &self.auth) {
            return (note, Err(FramingError::Returned(status.code)));
        }
        if self.length_void || self.chunked {
            self.size = None;
        }
        // `http_firstwrite`: a response to follow, or to make again with
        // credentials, is read no further than its head on a connection
        // that closes, and its body is dropped on one kept.
        let again = self.follow || self.auth.reload;
        if again && self.close {
            if let Some(size) = self.size
                && asked.max_filesize.is_some_and(|max| size > max.get())
            {
                return (note, Err(FramingError::FileTooLarge));
            }
            return (note, Ok(Framing::Abandoned));
        }
        let resume_from = asked.resume_from.filter(|_| !self.whole);
        self.ignore_body = again || (resume_from.is_some() && status.code == 416);
        if again {
            note.push(Note::IgnoringBody);
        }
        if let Some(from) = resume_from
            && !self.content_range
            && !self.ignore_body
        {
            if self.size != Some(from) {
                return (note, Err(FramingError::CannotResume));
            }
            // What is stored is the whole document.
            self.close = true;
            note.push(Note::AlreadyDownloaded);
            return (note, Ok(Framing::Abandoned));
        }
        // `http_size`.
        if let Some(size) = self.size {
            if self.ignore_body {
                note.push(Note::SizeWhileIgnoring);
            } else if asked.max_filesize.is_some_and(|max| size > max.get()) {
                return (note, Err(FramingError::FileTooLarge));
            }
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
    /// The current response may carry no body (1xx, 204, 304).
    pub(crate) fn bodyless(&self) -> bool {
        self.bodyless
    }

    pub(crate) fn close(&self) -> bool {
        self.close
    }

    /// The response announced trailers.
    #[cfg_attr(
        not(test),
        expect(dead_code, reason = "only a multiplexed response waits for them")
    )]
    pub(crate) fn trailer(&self) -> bool {
        self.trailer
    }

    /// Where the response points, as the server gave it.
    pub(crate) fn location(&self) -> Option<&[u8]> {
        self.location.as_deref()
    }

    /// Where the response redirects to, if it is followed.
    pub(crate) fn follow(&self) -> Option<&[u8]> {
        self.location.as_deref().filter(|_| self.follow)
    }

    /// The 401's and 407's challenges, taken for the handle to keep.
    pub(crate) fn take_challenges(&mut self) -> Offered {
        std::mem::take(&mut self.challenges)
    }

    /// What the final head led to in authenticating.
    pub(crate) fn auth(&self) -> &AuthAct {
        &self.auth
    }

    /// The body is read and dropped.
    pub(crate) fn ignore_body(&self) -> bool {
        self.ignore_body
    }

    /// The body's size as the head gives it.
    pub(crate) fn size(&self) -> Option<u64> {
        self.size
    }
}

/// The media type a `Content-Type:` line gives, its blanks trimmed
/// (`Curl_copy_header_value`); none for another line or an empty value,
/// which C ignores.
pub(crate) fn content_type(line: &[u8]) -> Option<&[u8]> {
    value_of(line, b"Content-Type:")?;
    fields::header_value(line).filter(|v| !v.is_empty())
}

/// The longest wait `Retry-After` is taken to ask for: six hours.
const MAX_RETRY_AFTER: u64 = 6 * 3600;

/// How long a `Retry-After:` line asks to wait, the calendar time being
/// `now` (`http_header_r`): until its date, or its leading number of
/// seconds, at most six hours; zero for a date passed or anything else.
/// A date is tried first, as a number may start one.
pub(crate) fn retry_after(line: &[u8], now: i64) -> Option<Duration> {
    let v = skip_blanks(value_of(line, b"Retry-After:")?);
    let secs = match date::parse(v) {
        Ok(at) => u64::try_from(at.saturating_sub(now)).unwrap_or(0),
        Err(BadDate) => {
            let digits = v.iter().take_while(|b| b.is_ascii_digit()).count();
            std::str::from_utf8(&v[..digits])
                .ok()
                .and_then(|d| d.parse::<i64>().ok())
                .map_or(0, |n| n as u64)
        }
    };
    Some(Duration::from_secs(secs.min(MAX_RETRY_AFTER)))
}

/// The rest of `line` after its name `name`, which includes the colon
/// (C's `HD_VAL`).
pub(crate) fn value_of<'l>(line: &'l [u8], name: &[u8]) -> Option<&'l [u8]> {
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
