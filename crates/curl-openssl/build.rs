//! Refuse an OpenSSL older than 3.0, or one that is not OpenSSL: openssl-sys
//! found the library, and says which it is.

// A build script is no library: the environment is read as cargo gives it.
#![allow(clippy::disallowed_methods)]

fn main() {
    println!("cargo::rerun-if-env-changed=DEP_OPENSSL_VERSION_NUMBER");
    println!("cargo::rerun-if-env-changed=DEP_OPENSSL_LIBRESSL_VERSION_NUMBER");
    if std::env::var_os("DEP_OPENSSL_LIBRESSL_VERSION_NUMBER").is_some() {
        panic!("LibreSSL is not supported: this build binds OpenSSL 3.0 or later");
    }
    let number = std::env::var("DEP_OPENSSL_VERSION_NUMBER")
        .expect("openssl-sys reports the version of the OpenSSL it found");
    let number = u64::from_str_radix(&number, 16).expect("openssl-sys reports it in hex");
    if number < 0x3000_0000 {
        panic!("OpenSSL {number:#x} is too old: this build needs 3.0 or later");
    }
}
