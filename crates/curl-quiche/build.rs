//! Tell the crate whether the library of the OpenSSL family openssl-sys
//! found is BoringSSL, the only one quiche runs over (C's CMake: "quiche
//! requires BoringSSL"): `cfg(boringssl)`. Over another the crate is
//! empty, so that a workspace built over the system's OpenSSL builds it
//! without linking what that OpenSSL lacks; a tool or shim built with
//! `quiche` over another fails to compile, the library it names missing.

// A build script is not the library: its environment is cargo's.
#![allow(clippy::disallowed_methods, clippy::disallowed_macros)]

fn main() {
    println!("cargo::rerun-if-env-changed=DEP_OPENSSL_BORINGSSL");
    println!("cargo::rustc-check-cfg=cfg(boringssl)");
    if std::env::var("DEP_OPENSSL_BORINGSSL").is_ok_and(|v| v == "true") {
        println!("cargo::rustc-cfg=boringssl");
    }
}
