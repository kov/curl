//! Refuse an OpenSSL older than 3.0, or one that is not OpenSSL: openssl-sys
//! found the library, and says which it is. Then decide where the
//! library looks for certificates to trust when a transfer names none,
//! as CMake decides it for the C build (CMakeLists.txt's `CURL_CA_BUNDLE`
//! and `CURL_CA_PATH`), and write it for the crate to read.

// A build script is no library: the environment is read as cargo gives
// it, and its text made as std makes it.
#![allow(clippy::disallowed_methods, clippy::disallowed_macros)]

use std::path::Path;

/// The bundles CMake looks for, in its order.
const BUNDLES: &[&str] = &[
    "/etc/ssl/certs/ca-certificates.crt",
    "/etc/pki/tls/certs/ca-bundle.crt",
    "/usr/share/ssl/certs/ca-bundle.crt",
    "/usr/local/share/certs/ca-root-nss.crt",
    "/etc/ssl/cert.pem",
];

/// The directory CMake looks in for certificates stored one per file.
const CA_PATH: &str = "/etc/ssl/certs";

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
    // 3.2 names the group a handshake agreed on itself.
    println!("cargo::rustc-check-cfg=cfg(ossl320)");
    if number >= 0x3020_0000 {
        println!("cargo::rustc-cfg=ossl320");
    }
    let (bundle, path) = ca_defaults();
    let out = Path::new(&std::env::var("OUT_DIR").expect("cargo names it")).join("ca.rs");
    let text = format!(
        "/// The file of certificates to trust when a transfer names none.\n\
         pub(crate) const CA_BUNDLE: Option<&str> = {bundle:?};\n\
         /// The directory of them, likewise.\n\
         pub(crate) const CA_PATH: Option<&str> = {path:?};\n"
    );
    std::fs::write(out, text).expect("the output directory is writable");
}

/// What one of CMake's two settings says: none, find it, or this.
enum Setting {
    None,
    Auto,
    Set(String),
}

fn setting(name: &str) -> Setting {
    println!("cargo::rerun-if-env-changed={name}");
    match std::env::var(name).as_deref() {
        Err(_) | Ok("auto") => Setting::Auto,
        Ok("none") => Setting::None,
        Ok("") => panic!("Invalid value of {name}. Use 'none', 'auto' or a path."),
        Ok(path) => Setting::Set(path.into()),
    }
}

/// The CA bundle and path as CMake decides them: each from the
/// environment if set there, else found on this machine unless it
/// builds for another; a bundle or path set explicitly stops the other
/// being looked for.
fn ca_defaults() -> (Option<String>, Option<String>) {
    let cross = std::env::var("TARGET").ok() != std::env::var("HOST").ok();
    let bundle = setting("CURL_CA_BUNDLE");
    let path = setting("CURL_CA_PATH");
    let find_bundle = matches!(bundle, Setting::Auto) && !cross;
    let find_path = matches!(path, Setting::Auto) && !cross;
    let mut bundle = match bundle {
        Setting::Set(b) => Some(b),
        Setting::None | Setting::Auto => None,
    };
    let mut path = match path {
        Setting::Set(p) => Some(p),
        Setting::None | Setting::Auto => None,
    };
    let skip = (bundle.is_some() && find_path) || (path.is_some() && find_bundle);
    if !skip {
        if find_bundle {
            bundle = BUNDLES
                .iter()
                .find(|b| Path::new(b).exists())
                .map(|b| b.to_string());
        }
        if find_path && hashed_certificates(CA_PATH) {
            path = Some(CA_PATH.into());
        }
    }
    (bundle, path)
}

/// Whether `dir` holds a certificate named as OpenSSL's hashed lookup
/// names them: eight hex digits, then `.0`.
fn hashed_certificates(dir: &str) -> bool {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return false;
    };
    entries.flatten().any(|e| {
        let name = e.file_name();
        let name = name.to_string_lossy();
        name.len() == 10
            && name.ends_with(".0")
            && name[..8]
                .bytes()
                .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
    })
}
