//! The Rust API of the curl rewrite.
//!
//! This crate is the product. The C ABI in `curl-sys-abi` and the `curl`
//! tool in `curl-tool` are built on it.

#![forbid(unsafe_code)]
// Tests may allocate infallibly; the non-test build is still checked.
#![cfg_attr(test, allow(clippy::disallowed_methods, clippy::disallowed_macros))]

pub mod conn;
pub mod cookie;
pub mod date;
mod deliver;
pub mod easy;
pub mod error;
pub mod handler;
mod hash;
pub mod id;
pub mod multi;
mod netrc;
pub mod options;
mod progress;
mod proto;
pub mod report;
mod save;
pub mod share;
mod text;
pub mod time;
mod trace;
mod upload;
pub mod url;
pub mod version;
