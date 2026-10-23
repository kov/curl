//! A `Mime` read as a request's body (`Curl_mime_read`, `cr_mime`): its
//! headers made, its size reckoned and its bytes given as C gives them,
//! in the same pieces.

use std::fs::File;
use std::io::{Read as _, Seek as _, SeekFrom};

use curl_alloc::{OutOfMemory, TryArc, TryVec as _};

use crate::components::Component;
use crate::deliver::Lifts;
use crate::error::ErrorKind;
use crate::handler::{Handler, Read, ReadHandler, Rewind, RewindFailed};
use crate::multi::state::StepCx;
use crate::multi::{Host, TransferCx};
use crate::proto::http1::request::UserHeaders;
use crate::trace;
use crate::upload::Readout;

use super::{
    BOUNDARY_LEN, Content, Encoder, FileData, MAX_LEVELS, Mime, Part, Reached, content_type_for,
};

/// The record of a part whose reaching no one keeps: the tree's own top.
static UNKEPT: Reached = Reached(None);

/// A boundary line: CRLF, two dashes, the boundary and CRLF.
const BOUNDARY_SIZE: u64 = 4 + BOUNDARY_LEN as u64 + 2;
/// The input an encoder holds (`ENCODING_BUFFER_SIZE`).
const ENCODING_BUFFER: usize = 256;
/// The longest line an encoder makes (`MAX_ENCODED_LINE_LENGTH`).
const MAX_LINE: usize = 76;
/// What a read with little room reads into first (`cr_mime_read`'s
/// `tmp`).
const SMALL_READ: usize = 256;

/// What C's `size_t` returns say, between the readers of a tree.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Got {
    /// This many bytes; none is the end.
    Bytes(usize),
    /// Nothing more in this fill (`STOP_FILLING`).
    Stop,
    Abort,
    Pause,
    /// `READ_ERROR`.
    Error,
    /// A handler gave more than its room, this many: the transfer fails
    /// at once.
    Funny(usize),
}

impl Got {
    /// What C's `Curl_mime_read` returns for it: the size, or one of the
    /// sizes standing for something else (`CURL_READFUNC_ABORT`,
    /// `CURL_READFUNC_PAUSE`, `STOP_FILLING`, `READ_ERROR`).
    fn c_size(self) -> u64 {
        match self {
            Got::Bytes(n) | Got::Funny(n) => n as u64,
            Got::Abort => 0x1000_0000,
            Got::Pause => 0x1000_0001,
            Got::Stop => u64::MAX - 1,
            Got::Error => u64::MAX,
        }
    }
}

/// How a part's names are quoted in its `Content-Disposition`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Escape {
    /// `"`, CR and LF percent-encoded, as HTML forms do.
    Form,
    /// `"` and `\` escaped with a backslash, with no way to say CR or LF
    /// (`CURLMIMEOPT_FORMESCAPE`, and mail).
    Backslash,
}

/// Why a reader could not be made.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum MakeError {
    OutOfMemory,
    /// More than `MAX_LEVELS` deep.
    TooLarge,
    /// A name or file name with a CR or LF, which a backslash cannot
    /// quote.
    BadName,
    /// The source could not read a file the tree was to send.
    Unreadable,
}

impl From<OutOfMemory> for MakeError {
    fn from(_: OutOfMemory) -> MakeError {
        MakeError::OutOfMemory
    }
}

impl MakeError {
    pub(crate) fn kind(self) -> ErrorKind {
        match self {
            MakeError::OutOfMemory => ErrorKind::OutOfMemory,
            MakeError::TooLarge => ErrorKind::TooLarge,
            MakeError::BadName => ErrorKind::BadFunctionArgument,
            MakeError::Unreadable => ErrorKind::ReadError,
        }
    }
}

/// The application's code a reader calls: a part's read and rewind
/// handlers; and the transfer's count of lifted pauses, which says
/// whether a pause a part keeps still holds.
pub(crate) trait Calls {
    fn read(&mut self, handler: &Handler<dyn ReadHandler>, buf: &mut [u8]) -> Read;
    fn rewind(&mut self, handler: &Handler<dyn Rewind>) -> Result<(), RewindFailed>;
    fn lifts(&self) -> Lifts;
}

/// The handlers called with the transfer's context.
struct StepCalls<'c, 'x, H: Host>(&'c mut StepCx<'x, H>);

impl<H: Host> Calls for StepCalls<'_, '_, H> {
    fn read(&mut self, handler: &Handler<dyn ReadHandler>, buf: &mut [u8]) -> Read {
        handler.read(&mut TransferCx::new(self.0), buf)
    }

    fn rewind(&mut self, handler: &Handler<dyn Rewind>) -> Result<(), RewindFailed> {
        handler.rewind(&mut TransferCx::new(self.0))
    }

    fn lifts(&self) -> Lifts {
        self.0.pause().lifts()
    }
}

/// Where a part's reading is (`mimestate` for a part).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum PartState {
    Begin,
    CurlHeaders,
    UserHeaders,
    Eoh,
    Body,
    Content,
    End,
}

/// Where a tree's reading is (`mimestate` for a `curl_mime`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum MimeState {
    Begin,
    Boundary1,
    Boundary2,
    Content,
    End,
}

/// How the last read of a part's content went, for those that stick
/// (`lastreadstatus`). A pause holds until the transfer's pause is
/// lifted, when the count it was kept with is passed (`mime_unpause`):
/// a fill that gave bytes before its handler paused gives the pause at
/// the next.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Last {
    Fine,
    End,
    Abort,
    Error,
    Paused(Lifts),
}

/// An encoder's input and line (`mime_encoder_state`).
#[derive(Debug)]
struct EncState {
    /// Where on its output line it is.
    pos: usize,
    /// Input not yet encoded is `buf[beg..end]`.
    beg: usize,
    end: usize,
    buf: [u8; ENCODING_BUFFER],
}

impl EncState {
    fn new() -> EncState {
        EncState {
            pos: 0,
            beg: 0,
            end: 0,
            buf: [0; ENCODING_BUFFER],
        }
    }

    fn clear(&mut self) {
        self.pos = 0;
        self.beg = 0;
        self.end = 0;
    }
}

/// The reading of a part's content.
#[derive(Debug)]
struct Source {
    /// In headers, the offset into the line read; in the content, the
    /// bytes of it read (`state.offset`).
    offset: u64,
    last: Last,
    file: Option<File>,
    /// The file came short: it is at its end (`feof`).
    file_eof: bool,
    /// The content's size before encoding, if known (`datasize`).
    size: Option<u64>,
    sub: Option<MimeCursor>,
}

/// The reading of a part.
#[derive(Debug)]
struct PartCursor {
    state: PartState,
    /// The header line being read, in the list the state names.
    hdr: usize,
    src: Source,
    enc: EncState,
    /// The headers the library makes (`curlheaders`).
    head: Vec<Vec<u8>>,
}

/// The reading of a tree.
#[derive(Debug)]
struct MimeCursor {
    state: MimeState,
    part: usize,
    offset: u64,
    parts: Vec<PartCursor>,
}

/// What a part is, to its reader: a part of the tree, or the top one
/// that holds the tree and sends no headers of its own.
#[derive(Clone, Copy)]
struct PartRef<'a> {
    name: Option<&'a [u8]>,
    filename: Option<&'a [u8]>,
    mime_type: Option<&'a [u8]>,
    user: &'a [Vec<u8>],
    encoder: Option<Encoder>,
    content: ContentRef<'a>,
    /// Its headers are not part of the body (`MIME_BODY_ONLY`).
    body_only: bool,
    reached: &'a Reached,
}

#[derive(Clone, Copy)]
enum ContentRef<'a> {
    None,
    Bytes(&'a [u8]),
    File(&'a FileData),
    Read {
        handler: &'a Handler<dyn ReadHandler>,
        rewind: Option<&'a Handler<dyn Rewind>>,
        size: Option<u64>,
    },
    Parts(&'a Mime),
}

impl<'a> PartRef<'a> {
    fn of(part: &'a Part) -> PartRef<'a> {
        PartRef {
            name: part.name.as_deref(),
            filename: part.filename.as_deref(),
            mime_type: part.mime_type.as_deref(),
            user: &part.headers,
            encoder: part.encoder,
            content: match &part.content {
                Content::None => ContentRef::None,
                Content::Bytes(b) => ContentRef::Bytes(b),
                Content::File(f) => ContentRef::File(f),
                Content::Read {
                    handler,
                    rewind,
                    size,
                } => ContentRef::Read {
                    handler,
                    rewind: rewind.as_ref(),
                    size: *size,
                },
                Content::Parts(m) => ContentRef::Parts(m),
            },
            body_only: false,
            reached: &part.reached,
        }
    }

    fn top(mime: &'a Mime) -> PartRef<'a> {
        PartRef {
            name: None,
            filename: None,
            mime_type: None,
            user: &[],
            encoder: None,
            content: ContentRef::Parts(mime),
            body_only: true,
            reached: &UNKEPT,
        }
    }
}

/// The value of the first of `lines` that is `name`, a colon, then
/// spaces (`search_header`).
fn search<'l>(lines: impl IntoIterator<Item = &'l [u8]>, name: &[u8]) -> Option<&'l [u8]> {
    lines.into_iter().find_map(|line| {
        let named = line.len() > name.len()
            && line[..name.len()].eq_ignore_ascii_case(name)
            && line[name.len()] == b':';
        named.then(|| {
            let value = &line[name.len() + 1..];
            let spaces = value.iter().take_while(|&&b| b == b' ').count();
            &value[spaces..]
        })
    })
}

/// Whether `line` is the header `name` (`match_header`).
fn is_header(line: &[u8], name: &[u8]) -> bool {
    search([line], name).is_some()
}

/// Whether a type is `target`, whatever its parameters
/// (`content_type_match`).
fn type_is(content_type: Option<&[u8]>, target: &[u8]) -> bool {
    content_type.is_some_and(|t| {
        t.len() >= target.len()
            && t[..target.len()].eq_ignore_ascii_case(target)
            && matches!(
                t.get(target.len()),
                None | Some(b'\t' | b'\r' | b'\n' | b' ' | b';')
            )
    })
}

/// `parts` joined into one header line.
fn line(parts: &[&[u8]]) -> Result<Vec<u8>, OutOfMemory> {
    let mut l = Vec::new();
    l.try_reserve_exact(parts.iter().map(|p| p.len()).sum())
        .map_err(|_| OutOfMemory)?;
    for p in parts {
        l.try_extend_from_slice(p)?;
    }
    Ok(l)
}

/// A name quoted for `Content-Disposition` (`escape_string`).
fn escape(name: &[u8], how: Escape) -> Result<Vec<u8>, OutOfMemory> {
    let mut out = Vec::new();
    for &b in name {
        let swap: &[u8] = match (how, b) {
            (Escape::Form, b'"') => b"%22",
            (Escape::Form, b'\r') => b"%0D",
            (Escape::Form, b'\n') => b"%0A",
            (Escape::Backslash, b'\\') => b"\\\\",
            (Escape::Backslash, b'"') => b"\\\"",
            _ => &[b],
        };
        out.try_extend_from_slice(swap)?;
    }
    Ok(out)
}

/// Make the cursor of `part` and its subparts, nothing read.
fn cursor(part: PartRef<'_>, depth: usize) -> Result<PartCursor, MakeError> {
    if depth > MAX_LEVELS {
        return Err(MakeError::TooLarge);
    }
    let (size, sub) = match part.content {
        ContentRef::None => (Some(0), None),
        ContentRef::Bytes(b) => (Some(b.len() as u64), None),
        ContentRef::File(f) => (f.size(), None),
        ContentRef::Read { size, .. } => (size, None),
        ContentRef::Parts(m) => {
            let mut parts = Vec::new();
            parts
                .try_reserve_exact(m.parts.len())
                .map_err(|_| OutOfMemory)?;
            for p in &m.parts {
                parts.try_push(cursor(PartRef::of(p), depth + 1)?)?;
            }
            let sub = MimeCursor {
                state: MimeState::Begin,
                part: 0,
                offset: 0,
                parts,
            };
            (None, Some(sub))
        }
    };
    Ok(PartCursor {
        state: PartState::Begin,
        hdr: 0,
        src: Source {
            offset: 0,
            last: Last::Fine,
            file: None,
            file_eof: false,
            size,
            sub,
        },
        enc: EncState::new(),
        head: Vec::new(),
    })
}

/// Make the headers of `part` and its subparts
/// (`Curl_mime_prepare_headers`): `content_type` and `disposition` are
/// what its parent says, `user` the lines it may find its own in.
fn prepare<'u>(
    part: PartRef<'_>,
    c: &mut PartCursor,
    content_type: Option<&[u8]>,
    disposition: Option<&[u8]>,
    user: &dyn Fn(&[u8]) -> Option<&'u [u8]>,
    escaping: Escape,
    depth: usize,
) -> Result<(), MakeError> {
    let depth = depth + 1;
    if depth > MAX_LEVELS {
        return Err(MakeError::TooLarge);
    }
    c.head.clear();
    let custom = part.mime_type.or_else(|| user(b"Content-Type"));
    let mut content_type = custom.or(content_type);
    if content_type.is_none() {
        content_type = match part.content {
            ContentRef::Parts(_) => Some(&b"multipart/mixed"[..]),
            ContentRef::File(f) => part
                .filename
                .and_then(content_type_for)
                .or_else(|| content_type_for(f.path()))
                .or_else(|| part.filename.map(|_| &b"application/octet-stream"[..])),
            _ => part.filename.and_then(content_type_for),
        };
    }
    let boundary = match part.content {
        ContentRef::Parts(m) => Some(m.boundary.line()),
        _ => None,
    };
    // Plain text is the default, and not said, but for a file in a form.
    if boundary.is_none()
        && custom.is_none()
        && type_is(content_type, b"text/plain")
        && part.filename.is_none()
    {
        content_type = None;
    }
    if user(b"Content-Disposition").is_none() {
        disposition_line(part, c, disposition, content_type, escaping)?;
    }
    if let Some(t) = content_type {
        let l = match &boundary {
            Some(b) => line(&[b"Content-Type: ", t, b"; boundary=", b])?,
            None => line(&[b"Content-Type: ", t])?,
        };
        c.head.try_push(l)?;
    }
    if user(b"Content-Transfer-Encoding").is_none()
        && let Some(e) = part.encoder
    {
        c.head
            .try_push(line(&[b"Content-Transfer-Encoding: ", e.name()])?)?;
    }
    if let (ContentRef::Parts(m), Some(sub)) = (part.content, c.src.sub.as_mut()) {
        let disposition =
            type_is(content_type, b"multipart/form-data").then_some(&b"form-data"[..]);
        for (p, pc) in m.parts.iter().zip(&mut sub.parts) {
            let own = |name: &[u8]| search(p.headers.iter().map(Vec::as_slice), name);
            prepare(PartRef::of(p), pc, None, disposition, &own, escaping, depth)?;
        }
    }
    Ok(())
}

/// The part's `Content-Disposition`, if it has one
/// (`add_content_disposition`).
fn disposition_line(
    part: PartRef<'_>,
    c: &mut PartCursor,
    disposition: Option<&[u8]>,
    content_type: Option<&[u8]>,
    escaping: Escape,
) -> Result<(), MakeError> {
    let named = part.name.is_some() || part.filename.is_some();
    let mut disposition = disposition;
    if disposition.is_none()
        && (named
            || content_type
                .is_some_and(|t| !(t.len() >= 10 && t[..10].eq_ignore_ascii_case(b"multipart/"))))
    {
        disposition = Some(b"attachment");
    }
    if disposition.is_some_and(|d| d.eq_ignore_ascii_case(b"attachment")) && !named {
        disposition = None;
    }
    let Some(disposition) = disposition else {
        return Ok(());
    };
    let breaks = |n: Option<&[u8]>| n.is_some_and(|n| n.iter().any(|&b| b == b'\r' || b == b'\n'));
    if escaping == Escape::Backslash && (breaks(part.name) || breaks(part.filename)) {
        return Err(MakeError::BadName);
    }
    let name = part.name.map(|n| escape(n, escaping)).transpose()?;
    let filename = part.filename.map(|n| escape(n, escaping)).transpose()?;
    let (n0, n1, n2): (&[u8], &[u8], &[u8]) = match &name {
        Some(n) => (b"; name=\"", n, b"\""),
        None => (b"", b"", b""),
    };
    let (f0, f1, f2): (&[u8], &[u8], &[u8]) = match &filename {
        Some(f) => (b"; filename=\"", f, b"\""),
        None => (b"", b"", b""),
    };
    let l = line(&[
        b"Content-Disposition: ",
        disposition,
        n0,
        n1,
        n2,
        f0,
        f1,
        f2,
    ])?;
    c.head.try_push(l)?;
    Ok(())
}

/// The size of the part as sent, if known (`mime_size`).
fn part_size(part: PartRef<'_>, c: &mut PartCursor) -> Option<u64> {
    if let (ContentRef::Parts(m), Some(sub)) = (part.content, c.src.sub.as_mut()) {
        c.src.size = multipart_size(m, sub);
    }
    let mut size = c.src.size;
    if let Some(e) = part.encoder {
        size = encoded_size(e, size);
    }
    let size = size?;
    if part.body_only {
        return Some(size);
    }
    let head: u64 = c.head.iter().map(|h| h.len() as u64 + 2).sum();
    let user: u64 = part
        .user
        .iter()
        .filter(|h| !is_header(h, b"Content-Type"))
        .map(|h| h.len() as u64 + 2)
        .sum();
    size.checked_add(head)?.checked_add(user)?.checked_add(2)
}

/// The size of a tree's parts between their boundaries (`multipart_size`):
/// unknown if any part's is, though every part's is reckoned.
fn multipart_size(m: &Mime, sub: &mut MimeCursor) -> Option<u64> {
    let mut size = Some(BOUNDARY_SIZE);
    for (p, pc) in m.parts.iter().zip(&mut sub.parts) {
        let sz = part_size(PartRef::of(p), pc);
        size = match (size, sz) {
            (Some(a), Some(b)) => a.checked_add(BOUNDARY_SIZE)?.checked_add(b),
            _ => None,
        };
    }
    size
}

/// The size of `size` bytes encoded, if known (the encoders' `sizefunc`).
fn encoded_size(e: Encoder, size: Option<u64>) -> Option<u64> {
    match e {
        Encoder::Binary | Encoder::EightBit | Encoder::SevenBit => size,
        Encoder::Base64 => {
            let size = size?;
            if size == 0 {
                return Some(0);
            }
            // C's limit against overflowing a `curl_off_t`.
            const MAX: u64 =
                ((i64::MAX as u64 / (MAX_LINE as u64 + 2)) * MAX_LINE as u64 / 4) * 3 - 3;
            if size > MAX {
                return None;
            }
            let chars = 4 * (1 + (size - 1) / 3);
            Some(chars + 2 * ((chars - 1) / MAX_LINE as u64))
        }
        // Only reading it tells.
        Encoder::QuotedPrintable => (size == Some(0)).then_some(0),
    }
}

/// Copy what is left of `bytes` then `trail` from `offset` into `buf`
/// (`readback_bytes`).
fn readback_bytes(offset: &mut u64, buf: &mut [u8], bytes: &[u8], trail: &[u8]) -> usize {
    let at = usize::try_from(*offset).unwrap_or(usize::MAX);
    let from = if bytes.len() > at {
        &bytes[at..]
    } else {
        let k = at - bytes.len();
        if k >= trail.len() {
            return 0;
        }
        &trail[k..]
    };
    let n = from.len().min(buf.len());
    buf[..n].copy_from_slice(&from[..n]);
    *offset += n as u64;
    n
}

/// Read as much of a file as fits, as `fread` does: all of the room
/// unless the file ends or fails first.
fn fread(file: &mut File, buf: &mut [u8]) -> (usize, bool) {
    let mut n = 0;
    while n < buf.len() {
        match file.read(&mut buf[n..]) {
            Ok(0) => break,
            Ok(k) => n += k,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(_) => return (n, true),
        }
    }
    (n, false)
}

/// Read a part's content as it is (`read_part_content`): at most one read
/// that calls out (a handler, a file) per fill, as `hasread` says.
fn read_content(
    part: PartRef<'_>,
    src: &mut Source,
    buf: &mut [u8],
    hasread: &mut bool,
    calls: &mut dyn Calls,
) -> Got {
    match src.last {
        Last::End => return Got::Bytes(0),
        Last::Abort => return Got::Abort,
        Last::Error => return Got::Error,
        Last::Paused(at) if at == calls.lifts() => return Got::Pause,
        Last::Paused(_) | Last::Fine => {}
    }
    let got = if src.size.is_some_and(|size| src.offset >= size) {
        // At the end of a part of known size: no read.
        Got::Bytes(0)
    } else {
        match part.content {
            ContentRef::None => Got::Bytes(0),
            ContentRef::Bytes(_) | ContentRef::File(_) | ContentRef::Read { .. }
                if buf.is_empty() =>
            {
                Got::Stop
            }
            ContentRef::Bytes(bytes) => {
                let at = usize::try_from(src.offset).expect("within the bytes");
                let n = (bytes.len() - at).min(buf.len());
                buf[..n].copy_from_slice(&bytes[at..at + n]);
                Got::Bytes(n)
            }
            ContentRef::File(_) if src.file.is_some() && src.file_eof => Got::Bytes(0),
            ContentRef::File(_) | ContentRef::Read { .. } if *hasread => Got::Stop,
            ContentRef::File(f) => {
                *hasread = true;
                if src.file.is_none() {
                    match curl_os::fs::open_read(f.c_path()) {
                        Ok(file) => src.file = Some(file),
                        Err(_) => {
                            src.last = Last::Error;
                            return Got::Error;
                        }
                    }
                }
                let file = src.file.as_mut().expect("opened above");
                match fread(file, buf) {
                    // C's `fread` gives what came before the failure, which
                    // then reads as the end of the file: of a regular file,
                    // the size checked at the body's end tells it.
                    (n, true) if f.size().is_some() => {
                        src.file_eof = true;
                        Got::Bytes(n)
                    }
                    // Of any other, C sends what came as all of it
                    // (DIVERGENCE.md).
                    (0, true) => Got::Error,
                    (n, failed) => {
                        src.file_eof |= n < buf.len() && !failed;
                        Got::Bytes(n)
                    }
                }
            }
            ContentRef::Read { handler, .. } => {
                *hasread = true;
                match calls.read(handler, buf) {
                    Read::Data(n) if n.get() > buf.len() => Got::Funny(n.get()),
                    Read::Data(n) => Got::Bytes(n.get()),
                    Read::Eof => Got::Bytes(0),
                    Read::Pause => Got::Pause,
                    Read::Abort => Got::Abort,
                    Read::Fail => Got::Error,
                }
            }
            ContentRef::Parts(m) => {
                let sub = src.sub.as_mut().expect("a cursor for the subparts");
                subparts_read(m, sub, buf, hasread, calls)
            }
        }
    };
    match got {
        Got::Stop => {}
        Got::Pause => src.last = Last::Paused(calls.lifts()),
        Got::Bytes(0) => src.last = Last::End,
        Got::Abort => src.last = Last::Abort,
        Got::Error | Got::Funny(_) => src.last = Last::Error,
        Got::Bytes(n) => {
            src.offset += n as u64;
            src.last = Last::Fine;
        }
    }
    got
}

/// Read and encode a part's content (`read_encoded_part_content`).
fn read_encoded(
    part: PartRef<'_>,
    c: &mut PartCursor,
    encoder: Encoder,
    buf: &mut [u8],
    hasread: &mut bool,
    calls: &mut dyn Calls,
) -> Got {
    let mut cursize = 0;
    let mut ateof = false;
    let some_or = |cursize: usize, got: Got| {
        if cursize > 0 {
            Got::Bytes(cursize)
        } else {
            got
        }
    };
    loop {
        if c.enc.beg < c.enc.end || ateof {
            match encode(encoder, &mut c.enc, &mut buf[cursize..], ateof) {
                Got::Bytes(0) if ateof => return Got::Bytes(cursize),
                Got::Bytes(0) => {}
                Got::Bytes(n) => {
                    cursize += n;
                    continue;
                }
                got => return some_or(cursize, got),
            }
        }
        // More input wanted, after what is held, moved to the start.
        c.enc.buf.copy_within(c.enc.beg..c.enc.end, 0);
        c.enc.end -= c.enc.beg;
        c.enc.beg = 0;
        if c.enc.end >= ENCODING_BUFFER {
            return some_or(cursize, Got::Error);
        }
        let end = c.enc.end;
        match read_content(part, &mut c.src, &mut c.enc.buf[end..], hasread, calls) {
            Got::Bytes(0) => ateof = true,
            Got::Bytes(n) => c.enc.end += n,
            Got::Funny(n) => return Got::Funny(n),
            got => return some_or(cursize, got),
        }
    }
}

/// Encode what `st` holds into `out` (the encoders' `encodefunc`).
fn encode(e: Encoder, st: &mut EncState, out: &mut [u8], ateof: bool) -> Got {
    match e {
        Encoder::Binary | Encoder::EightBit => {
            if out.is_empty() {
                return Got::Stop;
            }
            let n = out.len().min(st.end - st.beg);
            out[..n].copy_from_slice(&st.buf[st.beg..st.beg + n]);
            st.beg += n;
            Got::Bytes(n)
        }
        Encoder::SevenBit => {
            if out.is_empty() {
                return Got::Stop;
            }
            let n = out.len().min(st.end - st.beg);
            for (i, o) in out[..n].iter_mut().enumerate() {
                let b = st.buf[st.beg];
                if b & 0x80 != 0 {
                    return if i > 0 { Got::Bytes(i) } else { Got::Error };
                }
                *o = b;
                st.beg += 1;
            }
            Got::Bytes(n)
        }
        Encoder::Base64 => base64(st, out, ateof),
        Encoder::QuotedPrintable => quoted_printable(st, out, ateof),
    }
}

const BASE64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// The base64 encoder (`encoder_base64_read`).
fn base64(st: &mut EncState, out: &mut [u8], ateof: bool) -> Got {
    let mut size = out.len();
    let mut at = 0;
    while st.beg < st.end {
        // A full line ends first.
        if st.pos > MAX_LINE - 4 {
            if size < 2 {
                if at == 0 {
                    return Got::Stop;
                }
                break;
            }
            out[at..at + 2].copy_from_slice(b"\r\n");
            at += 2;
            st.pos = 0;
            size -= 2;
        }
        if size < 4 {
            if at == 0 {
                return Got::Stop;
            }
            break;
        }
        if st.end - st.beg < 3 {
            break;
        }
        let i = u32::from(st.buf[st.beg]) << 16
            | u32::from(st.buf[st.beg + 1]) << 8
            | u32::from(st.buf[st.beg + 2]);
        st.beg += 3;
        for (k, shift) in [18, 12, 6, 0].into_iter().enumerate() {
            out[at + k] = BASE64[((i >> shift) & 0x3F) as usize];
        }
        at += 4;
        st.pos += 4;
        size -= 4;
    }
    // At the end, what is held is flushed.
    if ateof {
        if size < 4 {
            if at == 0 {
                return Got::Stop;
            }
        } else if st.end != st.beg {
            let held = st.end - st.beg;
            let mut i = u32::from(st.buf[st.beg]) << 16;
            if held == 2 {
                i |= u32::from(st.buf[st.beg + 1]) << 8;
            }
            out[at] = BASE64[((i >> 18) & 0x3F) as usize];
            out[at + 1] = BASE64[((i >> 12) & 0x3F) as usize];
            out[at + 2] = b'=';
            out[at + 3] = b'=';
            st.beg += 1;
            if st.beg != st.end {
                out[at + 2] = BASE64[((i >> 6) & 0x3F) as usize];
                st.beg += 1;
            }
            at += 4;
            st.pos += 4;
        }
    }
    Got::Bytes(at)
}

/// How quoted-printable treats a byte (`qp_class`).
#[derive(Clone, Copy, PartialEq, Eq)]
enum Qp {
    Escaped,
    Plain,
    Space,
    Cr,
    Lf,
}

fn qp_class(b: u8) -> Qp {
    match b {
        b' ' | b'\t' => Qp::Space,
        b'\r' => Qp::Cr,
        b'\n' => Qp::Lf,
        b'=' => Qp::Escaped,
        0x21..=0x7E => Qp::Plain,
        _ => Qp::Escaped,
    }
}

/// Whether a CRLF or the end of the data is `n` bytes on: `None` if more
/// input is needed to tell (`qp_lookahead_eol`).
fn qp_eol_at(st: &EncState, ateof: bool, n: usize) -> Option<bool> {
    let n = n + st.beg;
    if n >= st.end && ateof {
        return Some(true);
    }
    if n + 2 > st.end {
        return if ateof { Some(false) } else { None };
    }
    Some(qp_class(st.buf[n]) == Qp::Cr && qp_class(st.buf[n + 1]) == Qp::Lf)
}

/// The quoted-printable encoder (`encoder_qp_read`).
fn quoted_printable(st: &mut EncState, out: &mut [u8], ateof: bool) -> Got {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let mut at = 0;
    while st.beg < st.end {
        let b = st.buf[st.beg];
        let mut enc = [b, HEX[usize::from(b >> 4)], HEX[usize::from(b & 0xF)]];
        let mut len = 1;
        let mut consumed = 1;
        match qp_class(b) {
            Qp::Plain => {}
            // Spacing is escaped before a CRLF.
            Qp::Space => match qp_eol_at(st, ateof, 1) {
                None => return Got::Bytes(at),
                Some(false) => {}
                Some(true) => {
                    enc[0] = b'=';
                    len = 3;
                }
            },
            // A CRLF goes as it is; a CR alone is escaped.
            Qp::Cr => match qp_eol_at(st, ateof, 0) {
                None => return Got::Bytes(at),
                Some(true) => {
                    enc[1] = b'\n';
                    len = 2;
                    consumed = 2;
                }
                Some(false) => {
                    enc[0] = b'=';
                    len = 3;
                }
            },
            Qp::Lf | Qp::Escaped => {
                enc[0] = b'=';
                len = 3;
            }
        }
        // What is encoded must fit on the line, the soft break with it.
        if enc[len - 1] != b'\n' {
            let mut soft = st.pos + len > MAX_LINE;
            if !soft && st.pos + len == MAX_LINE {
                // Only at the end of the data or before a CRLF.
                match qp_eol_at(st, ateof, consumed) {
                    None => return Got::Bytes(at),
                    Some(false) => soft = true,
                    Some(true) => {}
                }
            }
            if soft {
                enc = *b"=\r\n";
                len = 3;
                consumed = 0;
            }
        }
        if len > out.len() - at {
            if at == 0 {
                return Got::Stop;
            }
            break;
        }
        out[at..at + len].copy_from_slice(&enc[..len]);
        at += len;
        st.pos += len;
        if enc[len - 1] == b'\n' {
            st.pos = 0;
        }
        st.beg += consumed;
    }
    Got::Bytes(at)
}

/// Read a part: its headers, then its content (`readback_part`).
fn readback_part(
    part: PartRef<'_>,
    c: &mut PartCursor,
    buf: &mut [u8],
    hasread: &mut bool,
    calls: &mut dyn Calls,
) -> Got {
    let mut cursize = 0;
    while cursize < buf.len() {
        let room = &mut buf[cursize..];
        let mut sz = 0;
        match c.state {
            PartState::Begin => {
                part.reached.set(true);
                c.state = if part.body_only {
                    PartState::Body
                } else {
                    PartState::CurlHeaders
                };
                c.hdr = 0;
                c.src.offset = 0;
            }
            PartState::CurlHeaders => match c.head.get(c.hdr) {
                None => {
                    c.state = PartState::UserHeaders;
                    c.hdr = 0;
                    c.src.offset = 0;
                }
                Some(h) => {
                    sz = readback_bytes(&mut c.src.offset, room, h, b"\r\n");
                    if sz == 0 {
                        c.hdr += 1;
                        c.src.offset = 0;
                    }
                }
            },
            // The application's `Content-Type` was taken as the type.
            PartState::UserHeaders => match part.user.get(c.hdr) {
                None => {
                    c.state = PartState::Eoh;
                    c.src.offset = 0;
                }
                Some(h) if is_header(h, b"Content-Type") => {
                    c.hdr += 1;
                    c.src.offset = 0;
                }
                Some(h) => {
                    sz = readback_bytes(&mut c.src.offset, room, h, b"\r\n");
                    if sz == 0 {
                        c.hdr += 1;
                        c.src.offset = 0;
                    }
                }
            },
            PartState::Eoh => {
                sz = readback_bytes(&mut c.src.offset, room, b"\r\n", b"");
                if sz == 0 {
                    c.state = PartState::Body;
                    c.src.offset = 0;
                }
            }
            PartState::Body => {
                c.enc.clear();
                c.state = PartState::Content;
                c.src.offset = 0;
            }
            PartState::Content => {
                let got = match part.encoder {
                    Some(e) => read_encoded(part, c, e, room, hasread, calls),
                    None => read_content(part, &mut c.src, room, hasread, calls),
                };
                match got {
                    Got::Bytes(0) => {
                        c.state = PartState::End;
                        c.src.offset = 0;
                        // Its descriptor is let go as soon as it is read.
                        c.src.file = None;
                        return Got::Bytes(cursize);
                    }
                    Got::Bytes(n) => sz = n,
                    Got::Funny(n) => return Got::Funny(n),
                    got => {
                        return if cursize > 0 {
                            Got::Bytes(cursize)
                        } else {
                            got
                        };
                    }
                }
            }
            PartState::End => return Got::Bytes(cursize),
        }
        cursize += sz;
    }
    Got::Bytes(cursize)
}

/// Read a tree's parts between its boundaries (`mime_subparts_read`).
fn subparts_read(
    m: &Mime,
    mc: &mut MimeCursor,
    buf: &mut [u8],
    hasread: &mut bool,
    calls: &mut dyn Calls,
) -> Got {
    let mut cursize = 0;
    while cursize < buf.len() {
        let room = &mut buf[cursize..];
        let mut sz = 0;
        match mc.state {
            MimeState::Begin => {
                mc.state = MimeState::Boundary1;
                mc.part = 0;
                // The first boundary follows the blank line ending the
                // headers, so its CRLF is left out.
                mc.offset = 2;
            }
            MimeState::Boundary1 => {
                sz = readback_bytes(&mut mc.offset, room, b"\r\n--", b"");
                if sz == 0 {
                    mc.state = MimeState::Boundary2;
                    mc.offset = 0;
                }
            }
            MimeState::Boundary2 => {
                let trail: &[u8] = if mc.part < m.parts.len() {
                    b"\r\n"
                } else {
                    b"--\r\n"
                };
                sz = readback_bytes(&mut mc.offset, room, &m.boundary.line(), trail);
                if sz == 0 {
                    mc.state = MimeState::Content;
                    mc.offset = 0;
                }
            }
            MimeState::Content => {
                if mc.part >= m.parts.len() {
                    mc.state = MimeState::End;
                    mc.offset = 0;
                } else {
                    let part = PartRef::of(&m.parts[mc.part]);
                    match readback_part(part, &mut mc.parts[mc.part], room, hasread, calls) {
                        Got::Bytes(0) => {
                            mc.state = MimeState::Boundary1;
                            mc.part += 1;
                            mc.offset = 0;
                        }
                        Got::Bytes(n) => sz = n,
                        Got::Funny(n) => return Got::Funny(n),
                        got => {
                            return if cursize > 0 {
                                Got::Bytes(cursize)
                            } else {
                                got
                            };
                        }
                    }
                }
            }
            MimeState::End => return Got::Bytes(cursize),
        }
        cursize += sz;
    }
    Got::Bytes(cursize)
}

/// Start a part over (`mime_part_rewind`): whether it could be.
fn rewind_part(part: PartRef<'_>, c: &mut PartCursor, calls: &mut dyn Calls) -> bool {
    let target = if part.body_only {
        PartState::Body
    } else {
        PartState::Begin
    };
    c.enc.clear();
    let mut ok = true;
    if c.state > target {
        ok = match part.content {
            // Nothing to start over. C has no seek function for it and
            // fails (DIVERGENCE.md).
            ContentRef::None => true,
            ContentRef::Bytes(_) => true,
            ContentRef::File(f) => match (&mut c.src.file, f.size()) {
                // Not a regular file: no seek function.
                (_, None) => false,
                (None, Some(_)) => true,
                (Some(file), Some(_)) => file.seek(SeekFrom::Start(0)).is_ok(),
            },
            ContentRef::Read { rewind, .. } => rewind.is_some_and(|r| calls.rewind(r).is_ok()),
            ContentRef::Parts(m) => {
                let sub = c.src.sub.as_mut().expect("a cursor for the subparts");
                rewind_subparts(m, sub, calls)
            }
        };
    }
    if ok {
        c.state = target;
        c.hdr = 0;
        c.src.offset = 0;
        c.src.file_eof = false;
        part.reached.set(false);
    }
    c.src.last = Last::Fine;
    ok
}

/// Start a tree's parts over (`mime_subparts_seek`), every one of them
/// whatever the others did.
fn rewind_subparts(m: &Mime, mc: &mut MimeCursor, calls: &mut dyn Calls) -> bool {
    if mc.state == MimeState::Begin {
        return true;
    }
    let mut ok = true;
    for (p, pc) in m.parts.iter().zip(&mut mc.parts) {
        ok &= rewind_part(PartRef::of(p), pc, calls);
    }
    if ok {
        mc.state = MimeState::Begin;
        mc.part = 0;
        mc.offset = 0;
    }
    ok
}

/// Start over every part an earlier request's reading reached, as a new
/// reader starts a tree (`Curl_creader_set_mime`'s `mime_rewind`): a
/// handler's part is rewound, and fails it without a rewind; a regular file
/// is opened again, and one that is not fails it; bytes, and nothing, start
/// over as they are. Every part is tried, whatever the others did.
fn rewind_parts(m: &Mime, calls: &mut dyn Calls) -> bool {
    let mut ok = true;
    for p in &m.parts {
        if !p.reached.get() {
            continue;
        }
        let over = match &p.content {
            // Nothing to start over, where C fails (DIVERGENCE.md).
            Content::None | Content::Bytes(_) => true,
            Content::File(f) => f.size().is_some(),
            Content::Read { rewind, .. } => {
                rewind.as_ref().is_some_and(|r| calls.rewind(r).is_ok())
            }
            Content::Parts(sub) => rewind_parts(sub, calls),
        };
        if over {
            p.reached.set(false);
        }
        ok &= over;
    }
    ok
}

/// A tree read as one request's body (`cr_mime`).
#[derive(Debug)]
pub(crate) struct MimeReader {
    mime: TryArc<Mime>,
    /// The tree's own headers are the request's, not the body's
    /// (`MIME_BODY_ONLY`).
    body_only: bool,
    top: PartCursor,
    size: Option<u64>,
    /// Bytes given since the start or the last rewind (`read_len`).
    read: u64,
    seen_eos: bool,
    errored: Option<ErrorKind>,
    /// Read ahead for a read with little room: `small[start..end]`.
    small: [u8; SMALL_READ],
    small_start: usize,
    small_end: usize,
}

impl MimeReader {
    /// A reader of `mime`, its headers made for a request whose own lines
    /// are `request` (`set_post_reader`, `Curl_creader_set_mime`).
    pub(crate) fn new(
        mime: TryArc<Mime>,
        request: &UserHeaders,
        escaping: Escape,
    ) -> Result<MimeReader, MakeError> {
        MimeReader::make(mime, request, escaping, true)
    }

    /// A reader of `mime`, its headers made for `request`, that gives
    /// them first unless `body_only`.
    fn make(
        mime: TryArc<Mime>,
        request: &UserHeaders,
        escaping: Escape,
        body_only: bool,
    ) -> Result<MimeReader, MakeError> {
        let top_ref = |mime| {
            let mut top = PartRef::top(mime);
            top.body_only = body_only;
            top
        };
        let mut top = cursor(top_ref(&mime), 0)?;
        // The application's Content-Type types the body, which is a form
        // unless it says otherwise.
        let given = request.line_replacing(b"Content-Type").map(|l| {
            let value = l.get(13..).unwrap_or(b"");
            let spaces = value.iter().take_while(|&&b| b == b' ').count();
            &value[spaces..]
        });
        let content_type = given.or(Some(b"multipart/form-data"));
        let user = |name: &[u8]| search(request.lines(), name);
        prepare(
            top_ref(&mime),
            &mut top,
            content_type,
            None,
            &user,
            escaping,
            0,
        )?;
        let size = part_size(top_ref(&mime), &mut top);
        Ok(MimeReader {
            mime,
            body_only,
            top,
            size,
            read: 0,
            seen_eos: false,
            errored: None,
            small: [0; SMALL_READ],
            small_start: 0,
            small_end: 0,
        })
    }

    /// Start over the parts an earlier request reached, as the tree may
    /// have been read before (`Curl_creader_set_mime`'s `mime_rewind`):
    /// whether a part was is its `Reached`. Failing, SendFailRewind.
    pub(crate) fn start<H: Host>(&mut self, cx: &mut StepCx<'_, H>) -> Result<(), ErrorKind> {
        if rewind_parts(&self.mime, &mut StepCalls(cx)) {
            Ok(())
        } else {
            Err(ErrorKind::SendFailRewind)
        }
    }

    /// The header lines the request sends for the body.
    pub(crate) fn head(&self) -> &[Vec<u8>] {
        &self.top.head
    }

    /// The body's size, if known.
    pub(crate) fn size(&self) -> Option<u64> {
        self.size
    }

    /// Whether any of it was given (`cr_mime_needs_rewind`).
    pub(crate) fn needs_rewind(&self) -> bool {
        self.read > 0
    }

    /// Fill `buf` as one `Curl_mime_read` does: again while a fill gives
    /// nothing because it would call out twice.
    fn mime_read(&mut self, buf: &mut [u8], calls: &mut dyn Calls) -> Got {
        loop {
            let mut hasread = false;
            let top = PartRef::top(&self.mime);
            let top = PartRef {
                body_only: self.body_only,
                ..top
            };
            let got = readback_part(top, &mut self.top, buf, &mut hasread, calls);
            if got != Got::Stop {
                return got;
            }
        }
    }

    /// What the next read gives, sans-IO: `Got` as C's reader sees it.
    fn next(&mut self, buf: &mut [u8], calls: &mut dyn Calls) -> Got {
        let blen = self.room(buf.len());
        if self.small_start < self.small_end {
            let n = (self.small_end - self.small_start).min(blen);
            buf[..n].copy_from_slice(&self.small[self.small_start..self.small_start + n]);
            self.small_start += n;
            return Got::Bytes(n);
        }
        if self.reads_small(blen) {
            // An encoder may need more room than that for its next group.
            let mut small = [0u8; SMALL_READ];
            let got = self.mime_read(&mut small, calls);
            let Got::Bytes(got) = got else {
                return got;
            };
            self.small = small;
            self.small_start = 0;
            self.small_end = got;
            let n = got.min(blen);
            buf[..n].copy_from_slice(&self.small[..n]);
            self.small_start = n;
            return Got::Bytes(n);
        }
        self.mime_read(&mut buf[..blen], calls)
    }

    /// What of `len` a read may fill: no more than is left of a known
    /// size.
    fn room(&self, len: usize) -> usize {
        match self.size {
            Some(size) => {
                let remain = size.saturating_sub(self.read);
                len.min(usize::try_from(remain).unwrap_or(usize::MAX))
            }
            None => len,
        }
    }

    /// Whether a read of `blen` goes through the small buffer: nothing is
    /// held in it, and the room is too little for an encoder's group.
    fn reads_small(&self, blen: usize) -> bool {
        self.small_start == self.small_end && blen <= 4
    }

    /// Read into `buf`, which is not empty (`cr_mime_read`).
    pub(crate) fn read<H: Host>(
        &mut self,
        cx: &mut StepCx<'_, H>,
        buf: &mut [u8],
        pausable: bool,
    ) -> Result<Readout, ErrorKind> {
        let len = buf.len();
        let read = Component::Read;
        if let Some(e) = self.errored {
            let code = e.number();
            trace::of(
                cx,
                read,
                format_args!("cr_mime_read(len={len}) is errored -> {code}, eos=0"),
            );
            return Err(e);
        }
        if self.seen_eos {
            trace::of(
                cx,
                read,
                format_args!("cr_mime_read(len={len}) seen eos -> 0, eos=1"),
            );
            return Ok(Readout { n: 0, eos: true });
        }
        let blen = self.room(len);
        if self.reads_small(blen) {
            trace::of(
                cx,
                read,
                format_args!("cr_mime_read(len={blen}), small read, using tmp"),
            );
        }
        let got = self.next(buf, &mut StepCalls(cx));
        let nread = got.c_size();
        trace::of(
            cx,
            read,
            format_args!("cr_mime_read(len={blen}), mime_read() -> {nread}"),
        );
        let (outcome, said) = self.took(cx, got, blen, pausable);
        if said {
            let (code, n, eos) = match outcome {
                Ok(Readout { n, eos }) => (trace::Code(Ok(())), n, eos),
                Err(e) => (trace::Code(Err(e)), 0, false),
            };
            let total = crate::upload::Total(self.size);
            let done = self.read;
            trace::of(
                cx,
                read,
                format_args!(
                    "cr_mime_read(len={blen}, total={total}, read={done}) -> {code}, {n}, {}",
                    u8::from(eos)
                ),
            );
        }
        outcome
    }

    /// What a read of `blen` that `got` comes to, and whether C traces it
    /// (`cr_mime_read`, which returns before its trace from a short end
    /// and from a handler giving more than its room).
    fn took<H: Host>(
        &mut self,
        cx: &mut StepCx<'_, H>,
        got: Got,
        blen: usize,
        pausable: bool,
    ) -> (Result<Readout, ErrorKind>, bool) {
        let latch = |me: &mut MimeReader, cx: &mut StepCx<'_, H>, kind, why| {
            me.errored = Some(kind);
            Err(trace::fail(cx, kind, why))
        };
        let said = !matches!(got, Got::Funny(_))
            && !(got == Got::Bytes(0) && self.size.is_some_and(|size| self.read < size));
        let outcome = match got {
            Got::Bytes(0) => match self.size {
                Some(size) if self.read < size => {
                    let read = self.read;
                    Err(trace::fail(
                        cx,
                        ErrorKind::ReadError,
                        format_args!(
                            "client mime read EOF fail, only {read}/{size} of needed bytes read"
                        ),
                    ))
                }
                _ => {
                    self.seen_eos = true;
                    Ok(Readout { n: 0, eos: true })
                }
            },
            Got::Bytes(n) => {
                self.read += n as u64;
                self.seen_eos = self.size.is_some_and(|size| self.read >= size);
                Ok(Readout {
                    n,
                    eos: self.seen_eos,
                })
            }
            Got::Abort => latch(
                self,
                cx,
                ErrorKind::AbortedByCallback,
                format_args!("operation aborted by callback"),
            ),
            Got::Pause if !pausable => Err(trace::fail(
                cx,
                ErrorKind::ReadError,
                format_args!("Read callback asked for PAUSE when not supported"),
            )),
            Got::Pause => {
                trace::of(
                    cx,
                    Component::Read,
                    format_args!("cr_mime_read(len={blen}), paused by callback"),
                );
                cx.pause_mut().ask_send();
                Ok(Readout { n: 0, eos: false })
            }
            Got::Stop | Got::Error => latch(
                self,
                cx,
                ErrorKind::ReadError,
                format_args!("read error getting mime data"),
            ),
            Got::Funny(_) => latch(
                self,
                cx,
                ErrorKind::ReadError,
                format_args!("read function returned funny value"),
            ),
        };
        (outcome, said)
    }

    /// Start the body over (`cr_mime_cntrl`'s rewind): whether it could
    /// be.
    fn restart(&mut self, calls: &mut dyn Calls) -> bool {
        let top = PartRef {
            body_only: self.body_only,
            ..PartRef::top(&self.mime)
        };
        let ok = rewind_part(top, &mut self.top, calls);
        if ok {
            self.read = 0;
            self.seen_eos = false;
            self.errored = None;
            self.small_start = 0;
            self.small_end = 0;
        }
        ok
    }

    /// Start the body over, for a request that sends it again; failing,
    /// SendFailRewind.
    pub(crate) fn rewind<H: Host>(&mut self, cx: &mut StepCx<'_, H>) -> Result<(), ErrorKind> {
        if self.restart(&mut StepCalls(cx)) {
            return Ok(());
        }
        trace::fail(
            cx,
            ErrorKind::SendFailRewind,
            format_args!("Cannot rewind mime/post data"),
        );
        Err(trace::fail(
            cx,
            ErrorKind::SendFailRewind,
            format_args!("rewind of client reader 'cr-mime' failed: 65"),
        ))
    }
}

/// No handlers to call: a tree read outside a transfer has none that can
/// be.
struct NoCalls;

impl Calls for NoCalls {
    fn read(&mut self, _: &Handler<dyn ReadHandler>, _: &mut [u8]) -> Read {
        Read::Fail
    }

    fn rewind(&mut self, _: &Handler<dyn Rewind>) -> Result<(), RewindFailed> {
        Err(RewindFailed)
    }

    fn lifts(&self) -> Lifts {
        Lifts::default()
    }
}

/// The tree whole, as `curl_formget` reads it (`Curl_mime_read` of a top
/// part that is not `MIME_BODY_ONLY`): the headers that type it as a form,
/// a blank line and its body, to `out` in the pieces C reads, at most
/// 8 KiB each. A part a handler reads fails it, as no transfer is there
/// to call the handler with. `out` taking less than it was given fails it
/// too.
pub(crate) fn read_whole(
    mime: TryArc<Mime>,
    out: &mut dyn FnMut(&[u8]) -> usize,
) -> Result<(), ErrorKind> {
    let mut reader =
        MimeReader::make(mime, &UserHeaders::NONE, Escape::Form, false).map_err(MakeError::kind)?;
    let mut buf = [0u8; 8192];
    loop {
        match reader.mime_read(&mut buf, &mut NoCalls) {
            Got::Bytes(0) => return Ok(()),
            Got::Bytes(n) if out(&buf[..n]) == n => {}
            Got::Bytes(_) | Got::Stop | Got::Error | Got::Funny(_) | Got::Pause => {
                return Err(ErrorKind::ReadError);
            }
            Got::Abort => return Err(ErrorKind::AbortedByCallback),
        }
    }
}

#[cfg(test)]
pub(crate) mod testing {
    //! The reader without a transfer, for the tests.

    use super::*;

    impl MimeReader {
        /// The next read's outcome, with `calls` for the handlers.
        pub(crate) fn next_for_test(&mut self, buf: &mut [u8], calls: &mut dyn Calls) -> Got {
            self.next(buf, calls)
        }

        pub(crate) fn restart_for_test(&mut self, calls: &mut dyn Calls) -> bool {
            self.restart(calls)
        }

        pub(crate) fn start_for_test(&mut self, calls: &mut dyn Calls) -> bool {
            rewind_parts(&self.mime, calls)
        }

        /// A reader of the tree whole, its headers first, as
        /// `read_whole` makes it.
        pub(crate) fn whole_for_test(mime: TryArc<Mime>) -> MimeReader {
            MimeReader::make(mime, &UserHeaders::NONE, Escape::Form, false).unwrap()
        }
    }
}
