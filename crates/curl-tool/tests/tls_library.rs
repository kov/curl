//! What the tool says of the options its TLS library lacks: with
//! Schannel, C's tool warns that the proxy's CA path and the TLS 1.3
//! suites are ignored, and passes over the rest it lacks without a word
//! and without writing them to `--libcurl`'s program; with OpenSSL,
//! which has them, it says nothing and writes them all.
//!
//! The expectations are the C tool's: `CURL_TOOL_UNDER_TEST` names
//! another tool to run them on.

#![allow(clippy::disallowed_methods, clippy::disallowed_macros)]

use std::path::PathBuf;
use std::process::Command;

/// The tool's standard output and error for `args`, without a
/// configuration file.
fn run(args: &[&str]) -> (String, String) {
    let tool = std::env::var_os("CURL_TOOL_UNDER_TEST")
        .map_or_else(|| PathBuf::from(env!("CARGO_BIN_EXE_curl")), PathBuf::from);
    let out = Command::new(tool).arg("-q").args(args).output().unwrap();
    (
        String::from_utf8(out.stdout).unwrap(),
        String::from_utf8(out.stderr).unwrap(),
    )
}

/// The tool's standard error for `args`.
fn stderr(args: &[&str]) -> String {
    run(args).1
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

/// The options Schannel lacks that C's tool says nothing of are set
/// nowhere and left out of the program `--libcurl` writes, as libcurl
/// refuses them; OpenSSL takes them all, and they are written.
#[test]
fn options_the_library_lacks_are_not_written() {
    // A file that is there, as the tool checks a revocation list is.
    let crl = concat!(env!("CARGO_MANIFEST_DIR"), "/Cargo.toml");
    let (program, said) = run(&[
        "--libcurl",
        "-",
        "--crlfile",
        crl,
        "--curves",
        "X25519",
        "--sigalgs",
        "ECDSA+SHA256",
        "--cert-status",
        "--engine",
        "none",
        "file:///this/file/is/not/there",
    ]);
    for option in [
        "CURLOPT_CRLFILE",
        "CURLOPT_PROXY_CRLFILE",
        "CURLOPT_SSL_EC_CURVES",
        "CURLOPT_SSL_SIGNATURE_ALGORITHMS",
        "CURLOPT_SSL_VERIFYSTATUS",
        "CURLOPT_SSLENGINE",
    ] {
        let written = program.contains(&format!("curl_easy_setopt(curl, {option},"));
        assert_eq!(written, !cfg!(feature = "schannel"), "{option}: {program}");
    }
    // Neither is warned of.
    assert!(!said.contains("ignoring"), "{said}");
    // And the program is written all the same.
    assert!(program.contains("curl_easy_perform"), "{program}");
}
