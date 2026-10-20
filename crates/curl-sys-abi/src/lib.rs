//! libcurl's C ABI, translated onto `curl-core`.
//!
//! Everything C-shaped stops here: `CURLcode`, `long` options, varargs,
//! raw pointers and NUL-terminated strings are converted to and from the
//! Rust API at this boundary and go no further.
