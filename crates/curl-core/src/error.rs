//! Errors of the Rust API.
//!
//! Each API has its own error kind, one variant per way it can fail. The
//! kinds and their messages are generated from libcurl's, so `Display`
//! shows the text `curl_easy_strerror` and friends return.

#[rustfmt::skip]
mod kinds;

pub use kinds::{ErrorKind, MultiErrorKind, ShareErrorKind, UrlErrorKind};

use std::fmt;

/// How a transfer failed. The detail message `CURLOPT_ERRORBUFFER` shows
/// joins the kind with the C ABI.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Error {
    kind: ErrorKind,
}

impl Error {
    pub fn kind(&self) -> ErrorKind {
        self.kind
    }
}

impl From<ErrorKind> for Error {
    fn from(kind: ErrorKind) -> Error {
        Error { kind }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.kind.fmt(f)
    }
}

impl std::error::Error for Error {}
