//! Link the GSS-API library as the C build does, and take its version as
//! C's build takes it.
//!
//! MIT krb5 by default, as CMake's FindGSS prefers it: from pkg-config's
//! `mit-krb5-gssapi`, else from `krb5-config` (macOS's Kerberos); its
//! version as pkg-config or `krb5-config` says it.
//!
//! GNU GSS with the `gnu-gss` feature (C's `HAVE_GSSGNU`): the copy built
//! by `inventory/measure/deps.py` in `build/deps/gnugss`, unless
//! `CURL_GNUGSS_DIR` names another, its static library and Shishi's,
//! which gives it Kerberos; its version as `gss.h`'s `GSS_VERSION` has
//! it, which is what C's `curl -V` prints.
//!
//! Whether it can narrow SPNEGO's mechanisms is checked as CMake checks
//! it (`HAVE_GSS_SET_NEG_MECHS`). Off Windows, the table of the header's
//! values the tests compare `src/sys.rs` with is built from the header
//! C includes.

#![allow(clippy::disallowed_methods, clippy::disallowed_macros)]

use std::path::PathBuf;
use std::process::Command;

/// What the build found of the library.
struct Found {
    version: String,
    /// The linker's words for it, for the checks.
    libs: Vec<String>,
    /// Where its headers are, beyond the compiler's own paths.
    includes: Vec<PathBuf>,
}

fn main() {
    println!("cargo::rerun-if-env-changed=PKG_CONFIG_PATH");
    println!("cargo::rerun-if-env-changed=PKG_CONFIG_LIBDIR");
    println!("cargo::rustc-check-cfg=cfg(gss_set_neg_mechs)");
    println!("cargo::rustc-check-cfg=cfg(gss_gnu)");
    println!("cargo::rustc-check-cfg=cfg(gss_layout)");
    let windows = std::env::var("CARGO_CFG_TARGET_OS").is_ok_and(|os| os == "windows");
    let gnu = std::env::var_os("CARGO_FEATURE_GNU_GSS").is_some();
    let found = if gnu {
        assert!(!windows, "GNU GSS is not built for Windows here");
        println!("cargo::rustc-cfg=gss_gnu");
        gnu_gss()
    } else {
        match pkg_config_version() {
            Some(version) => {
                // MIT krb5 for Windows names it by its width.
                if windows {
                    println!("cargo::rustc-link-lib=gssapi64");
                } else {
                    curl_build::link("gssapi_krb5", "mit-krb5-gssapi");
                }
                let libs = curl_build::pkg_config("mit-krb5-gssapi", "--libs").unwrap_or_default();
                let includes = curl_build::include_dirs("mit-krb5-gssapi");
                Found {
                    version,
                    libs,
                    includes,
                }
            }
            None => krb5_config(),
        }
    };
    let version = found.version;
    assert!(
        !version.is_empty() && version.bytes().all(|b| b.is_ascii_graphic()),
        "the GSS-API library's version reads {version:?}"
    );
    println!("cargo::rustc-env=CURL_GSS_VERSION={version}");
    // MIT krb5 has had it since 1.8, and Windows' build is MIT's; Apple's
    // Kerberos and GNU GSS have none.
    if (windows && !gnu)
        || curl_build::function_exists("neg_mechs", "gss_set_neg_mechs", &found.libs)
    {
        println!("cargo::rustc-cfg=gss_set_neg_mechs");
    }
    // Windows' MIT krb5 is found by its environment, not by pkg-config:
    // its headers are not known here.
    if !windows {
        println!("cargo::rerun-if-changed=csrc/layout.c");
        let mut build = cc::Build::new();
        for dir in &found.includes {
            build.include(dir);
        }
        if gnu {
            build.define("CURL_GSS_GNU", None);
        }
        build
            .file("csrc/layout.c")
            .warnings_into_errors(true)
            .compile("curl_gssapi_layout");
        println!("cargo::rustc-cfg=gss_layout");
    }
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

/// The libraries `krb5-config --libs gssapi` names, linked, its words
/// for the checks, its headers, and its version with "Kerberos 5 release
/// " taken off, as FindGSS takes them.
fn krb5_config() -> Found {
    let run = |args: &[&str]| {
        let out = Command::new("krb5-config")
            .args(args)
            .output()
            .expect("pkg-config finds no mit-krb5-gssapi, and krb5-config runs");
        assert!(out.status.success(), "krb5-config {args:?} fails");
        String::from_utf8(out.stdout).expect("krb5-config's output is text")
    };
    let libs: Vec<String> = run(&["--libs", "gssapi"])
        .split_whitespace()
        .map(str::to_owned)
        .collect();
    for flag in &libs {
        if let Some(lib) = flag.strip_prefix("-l") {
            println!("cargo::rustc-link-lib={lib}");
        } else if let Some(dir) = flag.strip_prefix("-L") {
            println!("cargo::rustc-link-search=native={dir}");
        }
    }
    let includes = run(&["--cflags", "gssapi"])
        .split_whitespace()
        .filter_map(|w| w.strip_prefix("-I"))
        .map(PathBuf::from)
        .collect();
    let version = run(&["--version"]);
    let version = version.trim();
    let version = version
        .strip_prefix("Kerberos 5 release ")
        .unwrap_or(version)
        .to_owned();
    Found {
        version,
        libs,
        includes,
    }
}

/// GNU GSS and Shishi, their static libraries, and the libraries Shishi
/// needs (`libshishi.la`'s `dependency_libs`).
fn gnu_gss() -> Found {
    println!("cargo::rerun-if-env-changed=CURL_GNUGSS_DIR");
    let dir = match std::env::var_os("CURL_GNUGSS_DIR") {
        Some(dir) => PathBuf::from(dir),
        None => PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../build/deps/gnugss"),
    };
    let include = dir.join("include");
    let header = include.join("gss.h");
    let text = std::fs::read_to_string(&header).unwrap_or_else(|e| {
        panic!(
            "{}: {e}: build GNU GSS with inventory/measure/deps.py, or name it in CURL_GNUGSS_DIR",
            header.display()
        )
    });
    // `# define GSS_VERSION "1.0.4"`.
    let version = text
        .lines()
        .find_map(|l| {
            let words: Vec<&str> = l
                .trim_start()
                .strip_prefix('#')?
                .split_whitespace()
                .collect();
            match words[..] {
                ["define", "GSS_VERSION", v] => Some(v.trim_matches('"').to_owned()),
                _ => None,
            }
        })
        .expect("gss.h names its version");
    let lib = dir.join("lib");
    for archive in ["libgss.a", "libshishi.a"] {
        println!("cargo::rerun-if-changed={}", lib.join(archive).display());
    }
    println!("cargo::rustc-link-search=native={}", lib.display());
    println!("cargo::rustc-link-lib=static=gss");
    println!("cargo::rustc-link-lib=static=shishi");
    const PRIVATE: [&str; 4] = ["tasn1", "gnutls", "gcrypt", "gpg-error"];
    for private in PRIVATE {
        println!("cargo::rustc-link-lib={private}");
    }
    let mut libs = vec![
        format!("-L{}", lib.display()),
        "-lgss".into(),
        "-lshishi".into(),
    ];
    libs.extend(PRIVATE.iter().map(|l| format!("-l{l}")));
    Found {
        version,
        libs,
        includes: vec![include],
    }
}
