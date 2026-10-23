//! A multipart body (`lib/mime.c`): a tree of parts, each with its
//! content, names and headers, sent between boundaries.
//!
//! The tree is a value: it says what to send. How far it has been read
//! is the reader's (`read::MimeReader`), made for each request.

pub(crate) mod read;
#[cfg(test)]
mod tests;

use std::io;
use std::sync::atomic::{AtomicBool, Ordering};

use curl_alloc::{OutOfMemory, TryArc, TryVec as _};

use crate::handler::{Handler, ReadHandler, Rewind};

/// The dashes a boundary starts with (`MIME_BOUNDARY_DASHES`).
const BOUNDARY_DASHES: usize = 24;
/// Its random characters (`MIME_RAND_BOUNDARY_CHARS`).
const BOUNDARY_CHARS: usize = 22;
/// A whole boundary (`MIME_BOUNDARY_LEN`).
pub const BOUNDARY_LEN: usize = BOUNDARY_DASHES + BOUNDARY_CHARS;

/// The most levels a tree may nest (`MAX_MIME_LEVELS`).
pub const MAX_LEVELS: usize = 40;

/// What a boundary's characters are drawn from.
const ALNUM: &[u8; 62] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

/// What separates the parts of a `Mime`: 24 dashes and 22 letters and
/// digits.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Boundary([u8; BOUNDARY_CHARS]);

impl Boundary {
    /// One drawn from `next`, a 32-bit number for each character, a
    /// number at or past the largest multiple of 62 drawn again
    /// (`Curl_rand_alnum`).
    pub fn draw<E>(mut next: impl FnMut() -> Result<u32, E>) -> Result<Boundary, E> {
        const SPACE: u32 = ALNUM.len() as u32;
        let mut chars = [0u8; BOUNDARY_CHARS];
        for c in &mut chars {
            let r = loop {
                let r = next()?;
                if r < u32::MAX - u32::MAX % SPACE {
                    break r;
                }
            };
            *c = ALNUM[(r % SPACE) as usize];
        }
        Ok(Boundary(chars))
    }

    /// One drawn from the kernel's random numbers.
    pub fn random() -> io::Result<Boundary> {
        Boundary::draw(|| {
            let mut word = [0u8; 4];
            curl_os::random::fill(&mut word)?;
            Ok(u32::from_ne_bytes(word))
        })
    }

    /// The boundary as it goes on the wire, after its two dashes.
    pub fn line(&self) -> [u8; BOUNDARY_LEN] {
        let mut line = [b'-'; BOUNDARY_LEN];
        line[BOUNDARY_DASHES..].copy_from_slice(&self.0);
        line
    }
}

impl std::fmt::Debug for Boundary {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Boundary({})", self.0.escape_ascii())
    }
}

/// Parts between boundaries (`curl_mime`).
#[derive(Debug)]
pub struct Mime {
    boundary: Boundary,
    parts: Vec<Part>,
}

impl Mime {
    /// A tree with no parts yet.
    pub fn new(boundary: Boundary) -> Mime {
        Mime {
            boundary,
            parts: Vec::new(),
        }
    }

    pub fn boundary(&self) -> &Boundary {
        &self.boundary
    }

    pub fn parts(&self) -> &[Part] {
        &self.parts
    }

    /// `part` after the others (`curl_mime_addpart`); one without a
    /// record of its own of whether it was reached is given one.
    pub fn add(&mut self, mut part: Part) -> Result<(), OutOfMemory> {
        if part.reached.0.is_none() {
            part.reached = Reached::new()?;
        }
        self.parts.try_push(part)
    }

    /// How deep the tree nests: 1 for parts without subparts.
    pub fn depth(&self) -> usize {
        1 + self
            .parts
            .iter()
            .map(|p| match &p.content {
                Content::Parts(m) => m.depth(),
                _ => 0,
            })
            .max()
            .unwrap_or(0)
    }
}

/// One part of a `Mime` (`curl_mimepart`).
#[derive(Debug, Default)]
pub struct Part {
    /// The form field it fills (`curl_mime_name`).
    pub name: Option<Vec<u8>>,
    /// The name of the file it says it is (`curl_mime_filename`).
    pub filename: Option<Vec<u8>>,
    /// Its `Content-Type` (`curl_mime_type`); without one it is guessed
    /// from the file name.
    pub mime_type: Option<Vec<u8>>,
    /// Header lines of the application's, each without its line end
    /// (`curl_mime_headers`): one of the lines the library makes is left
    /// out if one of these names it.
    pub headers: Vec<Vec<u8>>,
    /// How its content is encoded (`curl_mime_encoder`).
    pub encoder: Option<Encoder>,
    pub content: Content,
    /// Whether a request's reading reached it since it last started over.
    pub reached: Reached,
}

/// Whether a request's reading reached a part since the part last started
/// over (C's part state past its start). C keeps it in the part from one
/// request, and one transfer, to the next, and starts over only a part
/// that was reached: a handler's part is rewound, one without a rewind
/// fails the request, and so does a file that is not regular, which has
/// no way back. The copies of a part a source gives each request share
/// one; `Mime::add` gives a part that has none its own.
#[derive(Clone, Debug, Default)]
pub struct Reached(Option<TryArc<AtomicBool>>);

impl Reached {
    /// A new record, not reached, that its clones share.
    pub fn new() -> Result<Reached, OutOfMemory> {
        Ok(Reached(Some(TryArc::try_new(AtomicBool::new(false))?)))
    }

    pub fn get(&self) -> bool {
        self.0.as_ref().is_some_and(|r| r.load(Ordering::Relaxed))
    }

    /// Say whether it was reached: set as a reading reaches it, cleared
    /// as it starts over.
    pub fn set(&self, reached: bool) {
        if let Some(r) = &self.0 {
            r.store(reached, Ordering::Relaxed);
        }
    }
}

/// What a part holds.
#[derive(Debug, Default)]
pub enum Content {
    /// Nothing.
    #[default]
    None,
    /// These bytes (`curl_mime_data`).
    Bytes(TryArc<Vec<u8>>),
    /// A file's (`curl_mime_filedata`), read as it is sent.
    File(FileData),
    /// What a handler reads, `size` bytes if known (`curl_mime_data_cb`).
    /// Its rewind is called before a request reads it if an earlier one
    /// reached it (`Part::reached`), and whenever the body must be sent
    /// again; it starts the content over. Without one, a part that was
    /// reached cannot be sent again.
    Read {
        handler: Handler<dyn ReadHandler>,
        rewind: Option<Handler<dyn Rewind>>,
        size: Option<u64>,
    },
    /// Parts of its own (`curl_mime_subparts`).
    Parts(Mime),
}

/// A file a part sends: its path, and its size if it is a regular file,
/// as it was when given.
#[derive(Debug)]
pub struct FileData {
    /// The path and a zero byte.
    path: Vec<u8>,
    size: Option<u64>,
}

/// A file that cannot be a part's.
#[derive(Debug, PartialEq, Eq)]
pub enum FileError {
    OutOfMemory,
    /// Its status could not be read, or the path holds a zero byte.
    Unreadable,
}

impl FileData {
    /// The file at `path`, its status read now (`curl_mime_filedata`).
    pub fn new(path: &[u8]) -> Result<FileData, FileError> {
        if path.contains(&0) {
            return Err(FileError::Unreadable);
        }
        let meta =
            curl_os::fs::with_c_name(path, curl_os::fs::stat).map_err(|_| FileError::Unreadable)?;
        let mut copy = Vec::new();
        copy.try_reserve_exact(path.len() + 1)
            .map_err(|_| FileError::OutOfMemory)?;
        copy.try_extend_from_slice(path)
            .and_then(|()| copy.try_push(0))
            .map_err(|_| FileError::OutOfMemory)?;
        Ok(FileData {
            path: copy,
            size: meta.is_file().then_some(meta.len()),
        })
    }

    /// The path, as given.
    pub fn path(&self) -> &[u8] {
        &self.path[..self.path.len() - 1]
    }

    fn c_path(&self) -> &std::ffi::CStr {
        std::ffi::CStr::from_bytes_with_nul(&self.path).expect("one zero byte, at the end")
    }

    /// Its size, if it is a regular file.
    pub fn size(&self) -> Option<u64> {
        self.size
    }

    /// The same file, its status as it was.
    pub fn try_clone(&self) -> Result<FileData, OutOfMemory> {
        let mut path = Vec::new();
        path.try_extend_from_slice(&self.path)?;
        Ok(FileData {
            path,
            size: self.size,
        })
    }
}

/// How a part's content is encoded (`Content-Transfer-Encoding`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Encoder {
    /// As it is.
    Binary,
    /// As it is.
    EightBit,
    /// As it is, but a byte past 127 fails the transfer.
    SevenBit,
    Base64,
    QuotedPrintable,
}

impl Encoder {
    /// The encoder a name says, in any case.
    pub fn from_name(name: &[u8]) -> Option<Encoder> {
        [
            Encoder::Binary,
            Encoder::EightBit,
            Encoder::SevenBit,
            Encoder::Base64,
            Encoder::QuotedPrintable,
        ]
        .into_iter()
        .find(|e| e.name().eq_ignore_ascii_case(name))
    }

    /// Its name, as `Content-Transfer-Encoding` says it.
    pub fn name(self) -> &'static [u8] {
        match self {
            Encoder::Binary => b"binary",
            Encoder::EightBit => b"8bit",
            Encoder::SevenBit => b"7bit",
            Encoder::Base64 => b"base64",
            Encoder::QuotedPrintable => b"quoted-printable",
        }
    }
}

/// Gives the tree a transfer sends (`CURLOPT_MIMEPOST`), asked for each
/// time a request with a body is built, so that a tree the application
/// changed since is sent as it is then. `None` sends an empty body.
pub trait MimeSource: Send + Sync {
    fn mime(&self) -> Result<Option<TryArc<Mime>>, MimeError>;
}

/// Why a source gave no tree.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MimeError {
    OutOfMemory,
    /// It nests more than `MAX_LEVELS` deep.
    TooDeep,
    /// A file it was to send could not be read when it was made.
    Unreadable,
}

impl From<OutOfMemory> for MimeError {
    fn from(_: OutOfMemory) -> MimeError {
        MimeError::OutOfMemory
    }
}

/// The tree whole, as `curl_formget` gives it: the headers that type it as
/// a form (`Content-Type: multipart/form-data; boundary=...`), a blank
/// line, then the body a request would send, handed to `out` a piece at a
/// time, at most 8 KiB each, as it is read. Each piece must be taken
/// whole: `out` says how much of it it took.
///
/// Outside a transfer there is no context to call a handler with, so a
/// part whose content a handler reads fails it with ReadError, as does a
/// file that cannot be read or a piece `out` did not take whole.
pub fn read_whole(
    mime: TryArc<Mime>,
    out: &mut dyn FnMut(&[u8]) -> usize,
) -> Result<(), crate::error::ErrorKind> {
    read::read_whole(mime, out)
}

/// A source that gives the same tree each time.
pub struct Fixed(pub TryArc<Mime>);

impl MimeSource for Fixed {
    fn mime(&self) -> Result<Option<TryArc<Mime>>, MimeError> {
        Ok(Some(self.0.clone()))
    }
}

/// The type a file name's extension suggests, if one of a few
/// (`Curl_mime_contenttype`).
pub fn content_type_for(filename: &[u8]) -> Option<&'static [u8]> {
    const TYPES: &[(&[u8], &[u8])] = &[
        (b".gif", b"image/gif"),
        (b".jpg", b"image/jpeg"),
        (b".jpeg", b"image/jpeg"),
        (b".png", b"image/png"),
        (b".svg", b"image/svg+xml"),
        (b".txt", b"text/plain"),
        (b".htm", b"text/html"),
        (b".html", b"text/html"),
        (b".pdf", b"application/pdf"),
        (b".xml", b"application/xml"),
    ];
    TYPES
        .iter()
        .find(|(ext, _)| {
            filename.len() >= ext.len()
                && filename[filename.len() - ext.len()..].eq_ignore_ascii_case(ext)
        })
        .map(|&(_, t)| t)
}
