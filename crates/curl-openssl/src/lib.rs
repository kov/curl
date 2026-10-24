//! OpenSSL for the curl rewrite, through openssl-sys's declarations: the
//! system's library, as the C build links it, 3.0 or later.
//!
//! TLS (`lib/vtls/openssl.c`), behind `curl_core::tls::TlsBackend`, and
//! Ed25519 for HTTP message signatures (`lib/curl_ed25519.c`), behind
//! `curl_core::libraries::Ed25519`.

#![cfg_attr(test, allow(clippy::disallowed_methods, clippy::disallowed_macros))]

mod bio;
mod cache;
mod cert;
mod certinfo;
mod ffi;
mod hostcheck;
mod sign;
mod ssl;
mod sys;
mod text;
mod x509;

pub use sign::ED25519;
pub use ssl::{OPENSSL, OpenSsl};
pub use sys::{init, version};

#[cfg(test)]
mod tests;
