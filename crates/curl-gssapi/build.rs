//! Link the GSS-API library as the C build does, and take its version as
//! CMake's FindGSS does: from pkg-config's `mit-krb5-gssapi` (MIT krb5),
//! else from `krb5-config` (macOS's Kerberos).

#![allow(clippy::disallowed_methods)]

use std::process::Command;

fn main() {
    println!("cargo::rerun-if-env-changed=PKG_CONFIG_PATH");
    println!("cargo::rerun-if-env-changed=PKG_CONFIG_LIBDIR");
    let version = match pkg_config_version() {
        Some(version) => {
            // MIT krb5 for Windows names it by its width.
            if std::env::var("CARGO_CFG_TARGET_OS").is_ok_and(|os| os == "windows") {
                println!("cargo::rustc-link-lib=gssapi64");
            } else {
                println!("cargo::rustc-link-lib=gssapi_krb5");
            }
            version
        }
        None => krb5_config(),
    };
    assert!(
        !version.is_empty() && version.bytes().all(|b| b.is_ascii_graphic()),
        "the GSS-API library's version reads {version:?}"
    );
    println!("cargo::rustc-env=CURL_KRB5_VERSION={version}");
}

/// `mit-krb5-gssapi`'s version, if pkg-config knows it.
fn pkg_config_version() -> Option<String> {
    let out = Command::new("pkg-config")
        .args(["--modversion", "mit-krb5-gssapi"])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let version = String::from_utf8(out.stdout).expect("the version is text");
    Some(version.trim().to_owned())
}

/// The libraries `krb5-config --libs gssapi` names, linked, and its
/// version with "Kerberos 5 release " taken off, as FindGSS takes them.
fn krb5_config() -> String {
    let run = |args: &[&str]| {
        let out = Command::new("krb5-config")
            .args(args)
            .output()
            .expect("pkg-config finds no mit-krb5-gssapi, and krb5-config runs");
        assert!(out.status.success(), "krb5-config {args:?} fails");
        String::from_utf8(out.stdout).expect("krb5-config's output is text")
    };
    for flag in run(&["--libs", "gssapi"]).split_whitespace() {
        if let Some(lib) = flag.strip_prefix("-l") {
            println!("cargo::rustc-link-lib={lib}");
        } else if let Some(dir) = flag.strip_prefix("-L") {
            println!("cargo::rustc-link-search=native={dir}");
        }
    }
    let version = run(&["--version"]);
    let version = version.trim();
    version
        .strip_prefix("Kerberos 5 release ")
        .unwrap_or(version)
        .to_owned()
}
