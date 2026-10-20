//! Fallible allocation.
//!
//! A failed allocation is an error, never an abort (`DESIGN.md`). The
//! standard library's infallible constructors and growing methods are
//! banned by `clippy.toml` everywhere else; this crate provides what
//! replaces them.

mod boxed;
mod grow;

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
