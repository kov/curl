//! Report the build's compile-time toggles, one `name: ON|OFF` per line.
//!
//! The test suites read this to decide which tests apply. The names are
//! those of `src/curlinfo.c`. A capability reads ON only once it is
//! implemented.

#![forbid(unsafe_code)]

/// The tool's TLS library, which says what it can do; the rest of it is
/// the tool's.
#[allow(dead_code)]
#[path = "../tlslib.rs"]
mod tlslib;

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
    ("DoH", true),
    ("HTTP-auth", true),
    ("Mime", true),
    ("netrc", true),
    ("parsedate", true),
    ("proxy", true),
    ("shuffle-dns", true),
    // Asked of the library: see `toggles`.
    ("resolv-threaded", false),
    // The type-checking macros of the C headers, which ship unchanged.
    ("typecheck", true),
    // Error codes have their full messages.
    ("verbose-strings", true),
    // Asked of the platform: see `toggles`.
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
    ("ssl-sessions", true),
    ("cert-status", true),
    // Asked of the platform: see `toggles`.
    ("getrlimit", true),
];

/// Each toggle, `httpsig` ON where the library signs messages,
/// `cert-status` ON where the TLS library checks a stapled status,
/// `resolv-threaded` ON when the library resolves with the
/// threaded resolver, and `override-dns` where a debug build's c-ares takes
/// `CURL_DNS_SERVER`. On Windows `wakeup` and `getrlimit` are OFF, as C's
/// build there has no wakeup socket pair (`ENABLE_WAKEUP`, not under
/// Winsock) and no `getrlimit`.
fn toggles() -> impl Iterator<Item = (&'static str, bool)> {
    let threaded = cfg!(feature = "threaded-resolver");
    let signs = curl_core::version::version()
        .features
        .contains(&curl_core::version::Feature::Httpsig);
    TOGGLES.iter().map(move |&(name, on)| match name {
        "resolv-threaded" => (name, threaded),
        "override-dns" => (name, !threaded && cfg!(feature = "debug-hooks")),
        "wakeup" | "getrlimit" => (name, on && cfg!(unix)),
        // A build without an Ed25519 library (Schannel's) signs nothing,
        // as C's build with it.
        "httpsig" => (name, on && signs),
        // Schannel checks no stapled status, as C's build with it.
        "cert-status" => (name, on && tlslib::support().cert_status),
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

    /// What the platform decides is reported as C's build there reports
    /// it: a wakeup socket pair and `getrlimit` on Unix, neither on
    /// Windows.
    #[test]
    fn the_platform_s_toggles_are_reported_as_c_s_build_there() {
        let on = |name| toggles().find(|&(n, _)| n == name).map(|(_, on)| on);
        assert_eq!(on("wakeup"), Some(cfg!(unix)));
        assert_eq!(on("getrlimit"), Some(cfg!(unix)));
    }

    /// Message signatures are reported as the build has them: with
    /// OpenSSL's Ed25519, GnuTLS's nettle or wolfSSL's wolfCrypt, not with
    /// Schannel, which has none, as C's builds with each.
    #[test]
    fn message_signatures_are_reported_as_the_tls_library_has_them() {
        let on = toggles().find(|&(n, _)| n == "httpsig").map(|(_, on)| on);
        assert_eq!(
            on,
            Some(cfg!(any(
                feature = "openssl-tls",
                feature = "gnutls",
                feature = "wolfssl"
            )))
        );
    }
}
