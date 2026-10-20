//! Errors of the Rust API.
//!
//! Each API has its own error kind, one variant per way it can fail. The
//! kinds and their messages are generated from libcurl's, so `Display`
//! shows the text `curl_easy_strerror` and friends return.

#[rustfmt::skip]
mod kinds;

pub use kinds::{ErrorKind, MultiErrorKind, ShareErrorKind, UrlErrorKind};
