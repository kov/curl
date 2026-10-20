//! Fallible allocation.
//!
//! A failed allocation is an error, never an abort (`DESIGN.md`). The
//! standard library's infallible constructors and growing methods are
//! banned by `clippy.toml` everywhere else; this crate provides what
//! replaces them.

// Tests may allocate infallibly; the non-test build is still checked.
#![cfg_attr(test, allow(clippy::disallowed_methods, clippy::disallowed_macros))]

mod boxed;
mod grow;
#[cfg(feature = "debug-hooks")]
pub mod track;

pub use boxed::try_box;
pub use grow::{TryString, TryVec, try_format};

/// An allocation failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OutOfMemory;

impl std::fmt::Display for OutOfMemory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("out of memory")
    }
}

impl std::error::Error for OutOfMemory {}

impl From<std::collections::TryReserveError> for OutOfMemory {
    fn from(_: std::collections::TryReserveError) -> Self {
        OutOfMemory
    }
}
