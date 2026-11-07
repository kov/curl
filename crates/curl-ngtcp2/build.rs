//! Link ngtcp2, its crypto for the build's TLS library and nghttp3, as the
//! C build does: ngtcp2 the copy built at the version curl's CI pins
//! (`inventory/measure/deps.py`), in `build/deps/ngtcp2` unless
//! `CURL_NGTCP2_DIR` names another, and nghttp3 the system's. On Windows
//! all three are vcpkg's libraries, beside the OpenSSL that `openssl-sys`
//! finds, unless `CURL_NGTCP2_DIR` names ngtcp2's.
//!
//! The crypto is the one for the TLS library the crate's feature names,
//! told to the code as `cfg(crypto = "...")`: with `openssl`, the library
//! `openssl-sys` found, OpenSSL's (`ngtcp2_crypto_ossl`, `ossl`) or, for
//! LibreSSL, the one over the QUIC API LibreSSL shares with quictls
//! (`ngtcp2_crypto_libressl`, C's build without `OPENSSL_QUIC_API2`,
//! `libressl`), or for AWS-LC and BoringSSL theirs, of one name
//! (`ngtcp2_crypto_boringssl`, `boringssl`), from the ngtcp2 built for
//! the fork (`build/deps/ngtcp2-<fork>`, named in `CURL_NGTCP2_DIR`);
//! with `gnutls`, GnuTLS's (`ngtcp2_crypto_gnutls`); with
//! `wolfssl`, wolfSSL's (`ngtcp2_crypto_wolfssl`). Exactly one is named,
//! as C builds over one TLS library.

// A build script is not the library: an allocation it cannot make may
// abort it, and its environment is cargo's.
#![allow(clippy::disallowed_methods, clippy::disallowed_macros)]

use std::path::PathBuf;

fn main() {
    println!("cargo::rerun-if-env-changed=CURL_NGTCP2_DIR");
    println!("cargo::rerun-if-env-changed=DEP_OPENSSL_LIBRESSL_VERSION_NUMBER");
    println!("cargo::rerun-if-env-changed=DEP_OPENSSL_AWSLC");
    println!("cargo::rerun-if-env-changed=DEP_OPENSSL_BORINGSSL");
    println!(
        "cargo::rustc-check-cfg=cfg(crypto, values(\"ossl\", \"libressl\", \"boringssl\", \"gnutls\", \"wolfssl\"))"
    );
    let named: Vec<&str> = ["openssl", "gnutls", "wolfssl"]
        .into_iter()
        .filter(|f| std::env::var_os(format!("CARGO_FEATURE_{}", f.to_uppercase())).is_some())
        .collect();
    let crypto = match named.as_slice() {
        ["openssl"] => {
            let fork = |name: &str| {
                std::env::var(format!("DEP_OPENSSL_{name}")).is_ok_and(|v| v == "true")
            };
            if fork("AWSLC") || fork("BORINGSSL") {
                "boringssl"
            } else if std::env::var_os("DEP_OPENSSL_LIBRESSL_VERSION_NUMBER").is_some() {
                "libressl"
            } else {
                "ossl"
            }
        }
        ["gnutls"] => "gnutls",
        ["wolfssl"] => "wolfssl",
        _ => panic!(
            "curl-ngtcp2 needs exactly one of its features `openssl`, `gnutls` and \
             `wolfssl`, the TLS library its crypto is for; it has {named:?}"
        ),
    };
    println!("cargo::rustc-cfg=crypto=\"{crypto}\"");
    let lib_name = format!("ngtcp2_crypto_{crypto}");
    if std::env::var("CARGO_CFG_TARGET_OS").is_ok_and(|os| os == "windows") {
        if let Some(dir) = std::env::var_os("CURL_NGTCP2_DIR") {
            let lib = PathBuf::from(dir).join("lib");
            println!("cargo::rustc-link-search=native={}", lib.display());
        }
        // vcpkg's names: import libraries of its DLLs, OpenSSL's with
        // their `lib` prefix, LibreSSL's without.
        let (ssl, libcrypto) = match crypto {
            "ossl" => ("libssl", "libcrypto"),
            "libressl" => ("ssl", "crypto"),
            _ => panic!("ngtcp2's {crypto} crypto is not built on Windows here"),
        };
        for lib in [lib_name.as_str(), "ngtcp2", "nghttp3", ssl, libcrypto] {
            println!("cargo::rustc-link-lib={lib}");
        }
        return;
    }
    let dir = match std::env::var_os("CURL_NGTCP2_DIR") {
        Some(dir) => PathBuf::from(dir),
        None => PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../build/deps/ngtcp2"),
    };
    let lib = dir.join("lib");
    println!("cargo::rerun-if-changed={}", lib.display());
    println!("cargo::rustc-link-search=native={}", lib.display());
    println!("cargo::rustc-link-lib=static={lib_name}");
    println!("cargo::rustc-link-lib=static=ngtcp2");
    // nghttp3 and the TLS library from where pkg-config finds them, where
    // that is outside the linker's own paths (Homebrew's on macOS).
    curl_build::link("nghttp3", "libnghttp3");
    match crypto {
        "ossl" | "libressl" => {
            for dir in curl_build::library_dirs("openssl") {
                println!("cargo::rustc-link-search=native={}", dir.display());
            }
            println!("cargo::rustc-link-lib=ssl");
            println!("cargo::rustc-link-lib=crypto");
        }
        // Linked statically by openssl-sys, from the fork's own directory
        // (`OPENSSL_DIR`), after the crypto as curl-openssl depends on it.
        "boringssl" => {}
        // After the crypto library that needs it, so that it is kept.
        "gnutls" => curl_build::link("gnutls", "gnutls"),
        // Linked statically by curl-wolfssl, which this crate depends on
        // so that it comes after the crypto library on the link line.
        _ => {}
    }
}
