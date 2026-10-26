//! The Rust API of the curl rewrite.
//!
//! This crate is the product. The C ABI in `curl-sys-abi` and the `curl`
//! tool in `curl-tool` are built on it.

#![forbid(unsafe_code)]
// Tests may allocate infallibly; the non-test build is still checked.
#![cfg_attr(test, allow(clippy::disallowed_methods, clippy::disallowed_macros))]

pub mod altsvc;
mod base64;
pub mod coding;
pub mod components;
pub mod conn;
pub mod cookie;
pub mod date;
mod deliver;
pub mod easy;
pub mod error;
pub mod gss;
pub mod handler;
mod hash;
pub mod hsts;
pub mod http2;
pub mod http3;
pub mod id;
pub mod idn;
pub mod libraries;
pub mod mime;
pub mod multi;
mod netrc;
pub mod options;
mod progress;
mod proto;
pub mod report;
mod save;
pub mod share;
#[cfg(test)]
mod test_cell;
mod text;
pub mod time;
pub mod tls;
mod trace;
#[cfg(test)]
mod untrusted;
mod upload;
pub mod url;
pub mod version;
