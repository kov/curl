//! What the tool says of the options its TLS library lacks: with
//! Schannel, C's tool warns that the proxy's CA path and the TLS 1.3
//! suites are ignored; with OpenSSL, which has them, nothing.
//!
//! The expectations are the C tool's: `CURL_TOOL_UNDER_TEST` names
//! another tool to run them on.

#![allow(clippy::disallowed_methods, clippy::disallowed_macros)]

use std::path::PathBuf;
use std::process::Command;

/// The tool's standard error for `args`, without a configuration file.
fn stderr(args: &[&str]) -> String {
    let tool = std::env::var_os("CURL_TOOL_UNDER_TEST")
        .map_or_else(|| PathBuf::from(env!("CARGO_BIN_EXE_curl")), PathBuf::from);
    let out = Command::new(tool).arg("-q").args(args).output().unwrap();
    String::from_utf8(out.stderr).unwrap()
}

/// `--capath` (which the proxy's takes too) and `--tls13-ciphers` are
/// warned of as ignored, in C's words, where Schannel is the library.
#[test]
fn options_the_library_lacks_are_warned_of() {
    let said = stderr(&[
        "--capath",
        "nowhere",
        "--tls13-ciphers",
        "TLS_AES_128_GCM_SHA256",
        "file:///this/file/is/not/there",
    ]);
    // A warning is wrapped at the terminal's width, each line after the
    // first a `Warning: ` of its own: joined again here.
    let said = said.replace("\r\n", "\n").replace("\nWarning: ", " ");
    let said = said.split_whitespace().collect::<Vec<_>>().join(" ");
    let warnings = [
        "ignoring setting the CA path for the proxy, not supported by libcurl with Schannel",
        "ignoring --tls13-ciphers, not supported by libcurl with Schannel",
    ];
    for warning in warnings {
        if cfg!(feature = "schannel") {
            assert!(said.contains(warning), "{warning}: {said}");
        } else {
            let (what, _) = warning.split_once(", not supported").unwrap();
            assert!(!said.contains(what), "{what}: {said}");
        }
    }
    // The transfer is tried all the same: the file is not found.
    assert!(said.contains("curl: (37)"), "{said}");
}
