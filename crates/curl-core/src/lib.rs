//! The Rust API of the curl rewrite.
//!
//! This crate is the product. The C ABI in `curl-sys-abi` and the `curl`
//! tool in `curl-tool` are built on it.

#![forbid(unsafe_code)]
// Tests may allocate infallibly; the non-test build is still checked.
#![cfg_attr(test, allow(clippy::disallowed_methods, clippy::disallowed_macros))]

pub mod error;
pub mod id;
mod multi;
pub mod time;
pub mod url;
pub mod version;
