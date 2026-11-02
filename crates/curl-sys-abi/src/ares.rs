//! c-ares, which a build of the threaded resolver does not link.

#[cfg(all(feature = "c-ares", not(feature = "threaded-resolver")))]
pub(crate) use curl_ares::version;
#[cfg(all(feature = "c-ares", not(feature = "threaded-resolver")))]
pub(crate) use curl_ares::version_number;

/// The library that answers names.
#[cfg(all(feature = "c-ares", not(feature = "threaded-resolver")))]
pub(crate) const LIBRARY: Option<&'static dyn curl_core::conn::io::DnsLibrary> =
    Some(&curl_ares::ARES);

#[cfg(not(all(feature = "c-ares", not(feature = "threaded-resolver"))))]
pub(crate) fn version() -> &'static str {
    ""
}

#[cfg(not(all(feature = "c-ares", not(feature = "threaded-resolver"))))]
pub(crate) fn version_number() -> u32 {
    0
}

/// The threaded resolver answers names; no library does.
#[cfg(not(all(feature = "c-ares", not(feature = "threaded-resolver"))))]
pub(crate) const LIBRARY: Option<&'static dyn curl_core::conn::io::DnsLibrary> = None;

#[cfg(not(any(feature = "c-ares", feature = "threaded-resolver")))]
compile_error!("a resolver is needed: the `c-ares` or the `threaded-resolver` feature");
