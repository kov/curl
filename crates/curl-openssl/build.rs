//! Refuse an OpenSSL older than 3.0 or a LibreSSL older than 3.4.1, as C
//! does: openssl-sys found the library, and says which it is; LibreSSL
//! takes C's `LIBRESSL_VERSION_NUMBER` branches (`cfg(libressl)`). Then
//! decide where the library looks for certificates to trust when a
//! transfer names none, as CMake decides it (`curl_build::write_ca_defaults`).

// A build script is no library: the environment is read as cargo gives
// it, and its text made as std makes it.
#![allow(clippy::disallowed_methods, clippy::disallowed_macros)]

fn main() {
    println!("cargo::rerun-if-env-changed=DEP_OPENSSL_VERSION_NUMBER");
    println!("cargo::rerun-if-env-changed=DEP_OPENSSL_LIBRESSL_VERSION_NUMBER");
    // LibreSSL: C's `LIBRESSL_VERSION_NUMBER` branches, 3.4.1 or later as
    // C requires it.
    println!("cargo::rustc-check-cfg=cfg(libressl)");
    // 3.2 names the group a handshake agreed on itself.
    println!("cargo::rustc-check-cfg=cfg(ossl320)");
    if let Ok(number) = std::env::var("DEP_OPENSSL_LIBRESSL_VERSION_NUMBER") {
        let number = u64::from_str_radix(&number, 16).expect("openssl-sys reports it in hex");
        if number < 0x3040_100f {
            panic!("LibreSSL {number:#x} is too old: this build needs 3.4.1 or later");
        }
        println!("cargo::rustc-cfg=libressl");
    } else {
        let number = std::env::var("DEP_OPENSSL_VERSION_NUMBER")
            .expect("openssl-sys reports the version of the OpenSSL it found");
        let number = u64::from_str_radix(&number, 16).expect("openssl-sys reports it in hex");
        if number < 0x3000_0000 {
            panic!("OpenSSL {number:#x} is too old: this build needs 3.0 or later");
        }
        if number >= 0x3020_0000 {
            println!("cargo::rustc-cfg=ossl320");
        }
    }
    curl_build::write_ca_defaults();
}
