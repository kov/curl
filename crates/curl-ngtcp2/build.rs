//! Link ngtcp2, its OpenSSL crypto and nghttp3, as the C build does:
//! ngtcp2 the copy built at the version curl's CI pins
//! (`inventory/measure/deps.py`), in `build/deps/ngtcp2` unless
//! `CURL_NGTCP2_DIR` names another, and nghttp3 the system's. On Windows
//! all three are vcpkg's libraries, beside the OpenSSL that `openssl-sys`
//! finds, unless `CURL_NGTCP2_DIR` names ngtcp2's.

// A build script is not the library: an allocation it cannot make may
// abort it, and its environment is cargo's.
#![allow(clippy::disallowed_methods, clippy::disallowed_macros)]

use std::path::PathBuf;

fn main() {
    println!("cargo::rerun-if-env-changed=CURL_NGTCP2_DIR");
    if std::env::var("CARGO_CFG_TARGET_OS").is_ok_and(|os| os == "windows") {
        if let Some(dir) = std::env::var_os("CURL_NGTCP2_DIR") {
            let lib = PathBuf::from(dir).join("lib");
            println!("cargo::rustc-link-search=native={}", lib.display());
        }
        // vcpkg's names: import libraries of its DLLs, OpenSSL's with
        // their `lib` prefix.
        for lib in [
            "ngtcp2_crypto_ossl",
            "ngtcp2",
            "nghttp3",
            "libssl",
            "libcrypto",
        ] {
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
    println!("cargo::rustc-link-lib=static=ngtcp2_crypto_ossl");
    println!("cargo::rustc-link-lib=static=ngtcp2");
    // nghttp3 and OpenSSL from where pkg-config finds them, where that is
    // outside the linker's own paths (Homebrew's on macOS).
    curl_build::link("nghttp3", "libnghttp3");
    for dir in curl_build::library_dirs("openssl") {
        println!("cargo::rustc-link-search=native={}", dir.display());
    }
    println!("cargo::rustc-link-lib=ssl");
    println!("cargo::rustc-link-lib=crypto");
}
