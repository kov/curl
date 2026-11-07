//! Tell the crate which library of the OpenSSL family it is built over,
//! and refuse one older than C accepts: openssl-sys found the library and
//! read its headers, and says which it is. Then decide where the library
//! looks for certificates to trust when a transfer names none, as CMake
//! decides it (`curl_build::write_ca_defaults`).
//!
//! The cfgs are C's macros, so that each branch of the crate is the
//! branch of `lib/vtls/openssl.c` it follows:
//!
//! - `ossl3`: OpenSSL 3.0 or later itself (`HAVE_OPENSSL3`), which no fork
//!   is; `ossl320` its 3.2 or later.
//! - `libressl`: LibreSSL 3.4.1 or later (`LIBRESSL_VERSION_NUMBER`).
//! - `awslc`, `boringssl`: AWS-LC (`OPENSSL_IS_AWSLC`) and BoringSSL
//!   (`OPENSSL_IS_BORINGSSL`), which AWS-LC's headers do not define; and
//!   `boringssl_like` for either (`HAVE_BORINGSSL_LIKE`).
//! - `no_ocsp`: the headers define `OPENSSL_NO_OCSP` (BoringSSL's do).
//! - `read_buffer_len`: `HAVE_SSL_CTX_SET_DEFAULT_READ_BUFFER_LEN`,
//!   OpenSSL's and AWS-LC's since its headers define
//!   `X509_V_ERR_EC_KEY_EXPLICIT_PARAMS` (1.61.0).

// A build script is no library: the environment is read as cargo gives
// it, and its text made as std makes it.
#![allow(clippy::disallowed_methods, clippy::disallowed_macros)]

fn main() {
    for var in [
        "VERSION_NUMBER",
        "LIBRESSL_VERSION_NUMBER",
        "AWSLC",
        "BORINGSSL",
        "CONF",
        "INCLUDE",
    ] {
        println!("cargo::rerun-if-env-changed=DEP_OPENSSL_{var}");
    }
    for cfg in [
        "ossl3",
        "ossl320",
        "libressl",
        "awslc",
        "boringssl",
        "boringssl_like",
        "no_ocsp",
        "read_buffer_len",
    ] {
        println!("cargo::rustc-check-cfg=cfg({cfg})");
    }
    let cfg = |name: &str| println!("cargo::rustc-cfg={name}");
    // openssl-sys says `true` for the fork its headers' macro names, and
    // no version number for either.
    let fork = |name: &str| std::env::var(format!("DEP_OPENSSL_{name}")).is_ok_and(|v| v == "true");
    if fork("AWSLC") {
        cfg("awslc");
        cfg("boringssl_like");
        // AWS-LC fixed its large buffers in 1.61.0, which also introduced
        // the macro C keys on.
        let include = std::env::var("DEP_OPENSSL_INCLUDE")
            .expect("openssl-sys names the include directory it found");
        let x509 = std::path::Path::new(&include).join("openssl/x509.h");
        println!("cargo::rerun-if-changed={}", x509.display());
        let header =
            std::fs::read_to_string(&x509).unwrap_or_else(|e| panic!("{}: {e}", x509.display()));
        if header.lines().any(|l| {
            l.split_whitespace()
                .take(2)
                .eq(["#define", "X509_V_ERR_EC_KEY_EXPLICIT_PARAMS"])
        }) {
            cfg("read_buffer_len");
        }
    } else if fork("BORINGSSL") {
        cfg("boringssl");
        cfg("boringssl_like");
    } else if let Ok(number) = std::env::var("DEP_OPENSSL_LIBRESSL_VERSION_NUMBER") {
        let number = u64::from_str_radix(&number, 16).expect("openssl-sys reports it in hex");
        if number < 0x3040_100f {
            panic!("LibreSSL {number:#x} is too old: this build needs 3.4.1 or later");
        }
        cfg("libressl");
    } else {
        let number = std::env::var("DEP_OPENSSL_VERSION_NUMBER")
            .expect("openssl-sys reports the version of the OpenSSL it found");
        let number = u64::from_str_radix(&number, 16).expect("openssl-sys reports it in hex");
        if number < 0x3000_0000 {
            panic!("OpenSSL {number:#x} is too old: this build needs 3.0 or later");
        }
        cfg("ossl3");
        cfg("read_buffer_len");
        if number >= 0x3020_0000 {
            cfg("ossl320");
        }
    }
    let conf = std::env::var("DEP_OPENSSL_CONF").unwrap_or_default();
    if conf.split(',').any(|c| c == "OPENSSL_NO_OCSP") {
        cfg("no_ocsp");
    }
    curl_build::write_ca_defaults();
}
