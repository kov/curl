//! Report the build's compile-time toggles, one `name: ON|OFF` per line.
//!
//! The test suites read this to decide which tests apply. The names are
//! those of `src/curlinfo.c`. A capability reads ON only once it is
//! implemented.

#![forbid(unsafe_code)]

const TOGGLES: &[(&str, bool)] = &[
    ("bindlocal", false),
    ("cookies", false),
    ("basic-auth", true),
    ("bearer-auth", true),
    ("digest", true),
    ("negotiate-auth", false),
    ("aws", false),
    ("httpsig", false),
    ("DoH", false),
    ("HTTP-auth", true),
    ("Mime", false),
    ("netrc", true),
    ("parsedate", false),
    ("proxy", false),
    ("shuffle-dns", false),
    ("resolv-threaded", false),
    // The type-checking macros of the C headers, which ship unchanged.
    ("typecheck", true),
    // Error codes have their full messages.
    ("verbose-strings", true),
    ("wakeup", true),
    ("headers-api", true),
    ("xattr", false),
    ("form-api", false),
    // `time_t` and `curl_off_t` are 64 bits wide.
    ("large-time", true),
    ("large-size", true),
    ("sha512-256", true),
    ("win32-ca-searchpath", false),
    ("win32-ca-search-safe", false),
    ("--libcurl", false),
    ("override-dns", false),
    ("ssl-sessions", false),
    ("cert-status", false),
    ("getrlimit", false),
];

fn main() {
    for (name, on) in TOGGLES {
        println!("{name}: {}", if *on { "ON" } else { "OFF" });
    }
}
