//! What the tool says of the options its TLS library lacks: with
//! Schannel, C's tool warns that the proxy's CA path and the TLS 1.3
//! suites are ignored, and passes over the rest it lacks without a word
//! and without writing them to `--libcurl`'s program; with GnuTLS, the
//! same of the TLS 1.3 suites, the curves, the signature algorithms and
//! the engine; with OpenSSL, which has them, it says nothing and writes
//! them all, but for what its fork lacks: LibreSSL the signature
//! algorithms, and BoringSSL the TLS 1.3 suites, warned of, and the
//! stapled status.
//!
//! The expectations are the C tool's: `CURL_TOOL_UNDER_TEST` names
//! another tool to run them on.

#![allow(clippy::disallowed_methods, clippy::disallowed_macros)]

use std::path::PathBuf;
use std::process::Command;

/// The tool's standard output and error for `args`, without a
/// configuration file.
fn run(args: &[&str]) -> (String, String) {
    run_env(args, &[])
}

/// The same, with `env` set for it.
fn run_env(args: &[&str], env: &[(&str, &str)]) -> (String, String) {
    let tool = std::env::var_os("CURL_TOOL_UNDER_TEST")
        .map_or_else(|| PathBuf::from(env!("CARGO_BIN_EXE_curl")), PathBuf::from);
    let mut command = Command::new(tool);
    for name in ["CURL_CA_BUNDLE", "SSL_CERT_DIR", "SSL_CERT_FILE"] {
        command.env_remove(name);
    }
    let out = command
        .envs(env.iter().copied())
        .arg("-q")
        .args(args)
        .output()
        .unwrap();
    (
        String::from_utf8(out.stdout).unwrap(),
        String::from_utf8(out.stderr).unwrap(),
    )
}

/// The tool's standard error for `args`.
fn stderr(args: &[&str]) -> String {
    run(args).1
}

/// Which of OpenSSL's forks the tool's library is, as its version names
/// it: a build over one is OpenSSL's but for what the fork lacks.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Fork {
    /// OpenSSL itself, or a library that is not OpenSSL's.
    None,
    LibreSsl,
    AwsLc,
    BoringSsl,
}

fn fork() -> Fork {
    let version = run(&["-V"]).0;
    let names = |name: &str| version.split_whitespace().any(|w| w.starts_with(name));
    if names("LibreSSL/") {
        Fork::LibreSsl
    } else if names("AWS-LC/") {
        Fork::AwsLc
    } else if names("BoringSSL") {
        Fork::BoringSsl
    } else {
        Fork::None
    }
}

/// `--capath` (which the proxy's takes too) and `--tls13-ciphers` are
/// warned of as ignored, in C's words, where Schannel is the library;
/// `--tls13-ciphers` alone where GnuTLS or BoringSSL is
/// (`HAVE_SSL_CTX_SET_CIPHERSUITES`), and `--capath` alone where Rustls
/// is.
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
    let named = |prefix: &str| {
        run(&["-V"])
            .0
            .split_whitespace()
            .find(|w| w.starts_with(prefix))
            .unwrap()
            .to_owned()
    };
    let boringssl = fork() == Fork::BoringSsl;
    let library = if boringssl {
        "BoringSSL".to_owned()
    } else if cfg!(feature = "gnutls") {
        named("GnuTLS/")
    } else if cfg!(feature = "rustls") {
        named("rustls-ffi/")
    } else {
        "Schannel".to_owned()
    };
    let warnings = [
        (
            format!(
                "ignoring setting the CA path for the proxy, not supported by libcurl with {library}"
            ),
            cfg!(any(feature = "schannel", feature = "rustls")),
        ),
        (
            format!("ignoring --tls13-ciphers, not supported by libcurl with {library}"),
            cfg!(any(feature = "schannel", feature = "gnutls")) || boringssl,
        ),
    ];
    for (warning, warned) in warnings {
        if warned {
            assert!(said.contains(&warning), "{warning}: {said}");
        } else {
            let (what, _) = warning.split_once(", not supported").unwrap();
            assert!(!said.contains(what), "{what}: {said}");
        }
    }
    // The transfer is tried all the same: the file is not found.
    assert!(said.contains("curl: (37)"), "{said}");
}

/// The options Schannel, GnuTLS, mbedTLS or wolfSSL lacks that C's tool says nothing of
/// are set nowhere and left out of the program `--libcurl` writes, as
/// libcurl refuses them; OpenSSL takes them all, and they are written.
/// LibreSSL takes all but the signature algorithms
/// (`HAVE_SSL_CTX_SET1_SIGALGS`), and BoringSSL all but the stapled
/// status (`OPENSSL_NO_OCSP`).
#[test]
fn options_the_library_lacks_are_not_written() {
    // A file that is there, as the tool checks a revocation list is.
    let crl = concat!(env!("CARGO_MANIFEST_DIR"), "/Cargo.toml");
    let fork = fork();
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
        let gnutls_lacks = matches!(
            option,
            "CURLOPT_SSL_EC_CURVES" | "CURLOPT_SSL_SIGNATURE_ALGORITHMS" | "CURLOPT_SSLENGINE"
        );
        let mbedtls_lacks = gnutls_lacks || option == "CURLOPT_SSL_VERIFYSTATUS";
        let wolfssl_lacks = (mbedtls_lacks && option != "CURLOPT_SSL_EC_CURVES")
            || matches!(option, "CURLOPT_CRLFILE" | "CURLOPT_PROXY_CRLFILE");
        let lacks = cfg!(feature = "schannel")
            || (cfg!(feature = "gnutls") && gnutls_lacks)
            || (cfg!(any(feature = "mbedtls", feature = "rustls")) && mbedtls_lacks)
            || (cfg!(feature = "wolfssl") && wolfssl_lacks)
            || (option == "CURLOPT_SSL_SIGNATURE_ALGORITHMS" && fork == Fork::LibreSsl)
            || (option == "CURLOPT_SSL_VERIFYSTATUS" && fork == Fork::BoringSsl);
        assert_eq!(written, !lacks, "{option}: {program}");
    }
    // Neither is warned of.
    assert!(!said.contains("ignoring"), "{said}");
    // And the program is written all the same.
    assert!(program.contains("curl_easy_perform"), "{program}");
}

/// `--engine list` lists the library's engines: OpenSSL's built-in
/// `dynamic` among them; none for Schannel, GnuTLS, mbedTLS, wolfSSL or Rustls, which have none,
/// nor for LibreSSL, AWS-LC or BoringSSL, which have none either
/// (`OPENSSL_NO_ENGINE`).
#[test]
fn the_engines_listed_are_the_library_s() {
    let (out, said) = run(&["--engine", "list"]);
    let out = out.replace("\r\n", "\n");
    assert!(out.starts_with("Build-time engines:\n"), "{out}{said}");
    if cfg!(any(
        feature = "schannel",
        feature = "gnutls",
        feature = "mbedtls",
        feature = "wolfssl",
        feature = "rustls"
    )) || fork() != Fork::None
    {
        assert_eq!(out, "Build-time engines:\n  <none>\n");
    } else {
        assert!(out.lines().any(|l| l == "  dynamic"), "{out}");
    }
}

/// The CA bundle the environment names is trusted unless the library
/// trusts the system's store by itself, as Schannel does, for which C's
/// tool reads none (`win32_using_schannel`).
#[test]
fn a_ca_bundle_from_the_environment_is_read_unless_the_library_trusts_the_system() {
    let (program, said) = run_env(
        &["--libcurl", "-", "file:///this/file/is/not/there"],
        &[("CURL_CA_BUNDLE", "/bundle")],
    );
    assert!(program.contains("curl_easy_perform"), "{program}{said}");
    let named = program.contains("curl_easy_setopt(curl, CURLOPT_CAINFO, \"/bundle\");");
    assert_eq!(named, !cfg!(feature = "schannel"), "{program}");
}

/// The tool's exit code and standard error for `args`.
fn exit(args: &[&str]) -> (Option<i32>, String) {
    let tool = std::env::var_os("CURL_TOOL_UNDER_TEST")
        .map_or_else(|| PathBuf::from(env!("CARGO_BIN_EXE_curl")), PathBuf::from);
    let out = Command::new(tool).arg("-q").args(args).output().unwrap();
    (out.status.code(), String::from_utf8(out.stderr).unwrap())
}

/// The library claims Encrypted Client Hello, as `curl -V` lists it.
fn has_ech() -> bool {
    run(&["-V"])
        .0
        .lines()
        .any(|l| l.starts_with("Features:") && l.split_whitespace().any(|w| w == "ECH"))
}

/// `--ech` is refused where the library has no ECH, whatever its word, as
/// C's tool refuses it (`feature_ech`); where it has, its words reach the
/// library as `CURLOPT_ECH`, the name, then the list, then the mode, each
/// as given, its prefix found in any case: a word the library does not
/// take fails the transfer, and a list in a file that cannot be read is
/// a bad use of the option, said so.
#[test]
fn ech_reaches_the_library_that_has_it() {
    let url = "file:///this/file/is/not/there";
    if !has_ech() {
        for word in ["true", "false", "ecl:QUJD", "nonsense"] {
            let (code, said) = exit(&["--ech", word, url]);
            assert_eq!(code, Some(2), "{word}: {said}");
            assert!(
                said.starts_with(
                    "curl: option --ech: the installed libcurl version does not support this\n"
                ),
                "{said}"
            );
        }
        return;
    }
    let (program, said) = run(&[
        "--libcurl",
        "-",
        "--ech",
        "true",
        "--ech",
        "ecl:QUJD",
        "--ech",
        "pn:public.example",
        url,
    ]);
    let set: Vec<_> = program
        .lines()
        .filter(|l| l.contains("CURLOPT_ECH"))
        .map(str::trim)
        .collect();
    assert_eq!(
        set,
        [
            "curl_easy_setopt(curl, CURLOPT_ECH, \"pn:public.example\");",
            "curl_easy_setopt(curl, CURLOPT_ECH, \"ecl:QUJD\");",
            "curl_easy_setopt(curl, CURLOPT_ECH, \"true\");",
        ],
        "{program}{said}"
    );
    // A prefix counts only with more than one byte after
    // it (`parse_ech`'s lengths): a word too short for its prefix is a
    // mode's, the last given of each kind is set, and the outer name
    // goes first.
    let (program, said) = run(&[
        "--libcurl",
        "-",
        "--ech",
        "pn:x",
        "--ech",
        "ecl:y",
        "--ech",
        "pn:ab",
        "--ech",
        "grease",
        url,
    ]);
    let set: Vec<_> = program
        .lines()
        .filter(|l| l.contains("CURLOPT_ECH"))
        .map(str::trim)
        .collect();
    assert_eq!(
        set,
        [
            "curl_easy_setopt(curl, CURLOPT_ECH, \"pn:ab\");",
            "curl_easy_setopt(curl, CURLOPT_ECH, \"grease\");",
        ],
        "{program}{said}"
    );
    // The library reads the prefixes in lower case only.
    for word in ["nonsense", "TRUE", "PN:public.example"] {
        let (code, said) = exit(&["--ech", word, url]);
        assert_eq!(code, Some(43), "{word}: {said}");
    }
    let (code, said) = exit(&["--ech", "ecl:@/this/file/is/not/there", url]);
    assert_eq!(code, Some(2), "{said}");
    // The warning wraps at a space, which ends its line.
    let said = said.replace("\nWarning: ", "");
    assert!(
        said.contains(
            "Could not read file \"/this/file/is/not/there\" specified for \"--ech ecl:\" option"
        ),
        "{said}"
    );
}
