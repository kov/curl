//! Report the build's compile-time toggles, one `name: ON|OFF` per line.
//!
//! The test suites read this to decide which tests apply. The names are
//! those of `src/curlinfo.c`. A capability reads ON only once it is
//! implemented.

#![forbid(unsafe_code)]

/// The toggles fixed whatever the build; `resolv-threaded` follows the
/// library's resolver (`toggles`).
const TOGGLES: &[(&str, bool)] = &[
    ("bindlocal", true),
    ("cookies", true),
    ("basic-auth", true),
    ("bearer-auth", true),
    ("digest", true),
    ("negotiate-auth", true),
    ("aws", true),
    ("httpsig", true),
    ("DoH", false),
    ("HTTP-auth", true),
    ("Mime", true),
    ("netrc", true),
    ("parsedate", true),
    ("proxy", true),
    ("shuffle-dns", false),
    // Asked of the library: see `toggles`.
    ("resolv-threaded", false),
    // The type-checking macros of the C headers, which ship unchanged.
    ("typecheck", true),
    // Error codes have their full messages.
    ("verbose-strings", true),
    ("wakeup", true),
    ("headers-api", true),
    ("xattr", true),
    ("form-api", true),
    // `time_t` and `curl_off_t` are 64 bits wide.
    ("large-time", true),
    ("large-size", true),
    ("sha512-256", true),
    ("win32-ca-searchpath", false),
    ("win32-ca-search-safe", false),
    ("--libcurl", true),
    ("override-dns", false),
    ("ssl-sessions", false),
    ("cert-status", true),
    ("getrlimit", true),
];

/// Each toggle, `resolv-threaded` ON when the library resolves with the
/// threaded resolver, which it claims as `AsynchDNS`.
fn toggles() -> impl Iterator<Item = (&'static str, bool)> {
    let threaded = curl_core::version::version().claims("AsynchDNS");
    TOGGLES.iter().map(move |&(name, on)| match name {
        "resolv-threaded" => (name, threaded),
        _ => (name, on),
    })
}

fn main() {
    for (name, on) in toggles() {
        println!("{name}: {}", if on { "ON" } else { "OFF" });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The threaded resolver is reported as C's curlinfo reports it, which
    /// the test suites read to run its tests.
    #[test]
    fn the_threaded_resolver_is_reported_as_the_library_has_it() {
        let threaded = toggles().find(|&(n, _)| n == "resolv-threaded");
        assert_eq!(
            threaded,
            Some(("resolv-threaded", cfg!(feature = "threaded-resolver")))
        );
    }
}
