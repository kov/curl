//! Link MIT krb5's GSS-API library, as the C build does, and take its
//! version as CMake's FindGSS does: from pkg-config's `mit-krb5-gssapi`.

use std::process::Command;

fn main() {
    println!("cargo::rustc-link-lib=gssapi_krb5");
    println!("cargo::rerun-if-env-changed=PKG_CONFIG_PATH");
    println!("cargo::rerun-if-env-changed=PKG_CONFIG_LIBDIR");
    let out = Command::new("pkg-config")
        .args(["--modversion", "mit-krb5-gssapi"])
        .output()
        .expect("pkg-config runs");
    assert!(
        out.status.success(),
        "pkg-config finds no mit-krb5-gssapi: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let version = String::from_utf8(out.stdout).expect("the version is text");
    let version = version.trim();
    assert!(
        !version.is_empty() && version.bytes().all(|b| b.is_ascii_graphic()),
        "mit-krb5-gssapi's version reads {version:?}"
    );
    println!("cargo::rustc-env=CURL_KRB5_VERSION={version}");
}
