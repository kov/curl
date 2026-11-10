//! What answers names: c-ares (C's `--enable-ares`), or the threaded
//! resolver (`--enable-threaded-resolver`), which links no library and
//! wins where both are asked for.

#[cfg(not(any(feature = "c-ares", feature = "threaded-resolver")))]
compile_error!("a resolver is needed: the `c-ares` or the `threaded-resolver` feature");

#[cfg(all(feature = "c-ares", not(feature = "threaded-resolver")))]
pub use curl_ares::{version, version_number};

/// The library that answers names.
#[cfg(all(feature = "c-ares", not(feature = "threaded-resolver")))]
pub const LIBRARY: Option<&'static dyn curl_core::conn::io::DnsLibrary> = Some(&curl_ares::ARES);

/// None: the threaded resolver answers names.
#[cfg(not(all(feature = "c-ares", not(feature = "threaded-resolver"))))]
pub fn version() -> &'static str {
    ""
}

/// None: the threaded resolver answers names.
#[cfg(not(all(feature = "c-ares", not(feature = "threaded-resolver"))))]
pub fn version_number() -> u32 {
    0
}

/// The threaded resolver answers names; no library does.
#[cfg(not(all(feature = "c-ares", not(feature = "threaded-resolver"))))]
pub const LIBRARY: Option<&'static dyn curl_core::conn::io::DnsLibrary> = None;
