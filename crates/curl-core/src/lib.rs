//! The Rust API of the curl rewrite.
//!
//! This crate is the product. The C ABI in `curl-sys-abi` and the `curl`
//! tool in `curl-tool` are built on it.

#![forbid(unsafe_code)]
// Tests may allocate infallibly; the non-test build is still checked.
#![cfg_attr(test, allow(clippy::disallowed_methods, clippy::disallowed_macros))]

pub mod conn;
mod deliver;
pub mod easy;
pub mod error;
pub mod handler;
pub mod id;
pub mod multi;
pub mod options;
mod progress;
mod proto;
pub mod report;
pub mod time;
mod upload;
pub mod url;
pub mod version;
