//! Errors of the Rust API.
//!
//! Each API has its own error kind, one variant per way it can fail. The
//! kinds and their messages are generated from libcurl's, so `Display`
//! shows the text `curl_easy_strerror` and friends return.

#[rustfmt::skip]
mod kinds;

pub use kinds::{ErrorKind, MultiErrorKind, ShareErrorKind, UrlErrorKind};

use std::fmt;

use curl_alloc::TryVec;

/// How a transfer failed: the kind, and the reason in the words the
/// transfer gave, when it gave one (`CURLOPT_ERRORBUFFER`).
#[derive(Debug, PartialEq, Eq)]
pub struct Error {
    kind: ErrorKind,
    /// Dropped if keeping it runs out of memory; the kind is kept.
    detail: Option<Vec<u8>>,
}

impl Error {
    /// `kind`, with a copy of `detail`.
    pub(crate) fn with_detail(kind: ErrorKind, detail: Option<&[u8]>) -> Error {
        let detail = detail.and_then(|d| {
            let mut kept = Vec::new();
            kept.try_extend_from_slice(d).ok().map(|()| kept)
        });
        Error { kind, detail }
    }

    pub fn kind(&self) -> ErrorKind {
        self.kind
    }

    /// Why, in the transfer's words; not always text.
    pub fn detail(&self) -> Option<&[u8]> {
        self.detail.as_deref()
    }
}

impl From<ErrorKind> for Error {
    fn from(kind: ErrorKind) -> Error {
        Error { kind, detail: None }
    }
}

/// The detail when there is one, else the kind's message.
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.detail {
            Some(detail) => String::from_utf8_lossy(detail).fmt(f),
            None => self.kind.fmt(f),
        }
    }
}

impl std::error::Error for Error {}
