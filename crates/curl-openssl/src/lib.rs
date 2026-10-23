//! OpenSSL for the curl rewrite, through openssl-sys's declarations: the
//! system's library, as the C build links it, 3.0 or later.
//!
//! Ed25519 for HTTP message signatures (`lib/curl_ed25519.c`), behind
//! `curl_core::libraries::Ed25519`.

#![cfg_attr(test, allow(clippy::disallowed_methods, clippy::disallowed_macros))]

mod sign;
mod sys;

pub use sign::ED25519;
pub use sys::init;

#[cfg(test)]
mod tests;
