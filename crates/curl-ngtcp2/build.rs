//! Link ngtcp2, its OpenSSL crypto and nghttp3, as the C build does:
//! ngtcp2 the copy built at the version curl's CI pins
//! (`inventory/measure/deps.py`), in `build/deps/ngtcp2` unless
//! `CURL_NGTCP2_DIR` names another, and nghttp3 the system's.

// A build script is not the library: an allocation it cannot make may
// abort it, and its environment is cargo's.
#![allow(clippy::disallowed_methods)]

use std::path::PathBuf;

fn main() {
    println!("cargo::rerun-if-env-changed=CURL_NGTCP2_DIR");
    let dir = match std::env::var_os("CURL_NGTCP2_DIR") {
        Some(dir) => PathBuf::from(dir),
        None => PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../build/deps/ngtcp2"),
    };
    let lib = dir.join("lib");
    println!("cargo::rerun-if-changed={}", lib.display());
    println!("cargo::rustc-link-search=native={}", lib.display());
    println!("cargo::rustc-link-lib=static=ngtcp2_crypto_ossl");
    println!("cargo::rustc-link-lib=static=ngtcp2");
    println!("cargo::rustc-link-lib=nghttp3");
    println!("cargo::rustc-link-lib=ssl");
    println!("cargo::rustc-link-lib=crypto");
}
