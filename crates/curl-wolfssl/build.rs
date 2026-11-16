//! Link wolfSSL, as the C build does: the copy built at the version
//! curl's CI pins (`inventory/measure/deps.py`), in `build/deps/wolfssl`
//! unless `CURL_WOLFSSL_DIR` names another, its static library, refusing
//! a version before 5.0.0 as C does (`wolfssl.c`'s `#error`); decide
//! where the library looks for certificates to trust when a transfer
//! names none, as CMake decides it; and build the table of the headers'
//! values (`csrc/layout.c`), which also refuses a build of the library
//! configured otherwise than the binding follows.

// A build script is no library: aborting on a failed allocation is fine.
#![allow(clippy::disallowed_methods, clippy::disallowed_macros)]

use std::path::PathBuf;

fn main() {
    println!("cargo::rerun-if-env-changed=CURL_WOLFSSL_DIR");
    let dir = match std::env::var_os("CURL_WOLFSSL_DIR") {
        Some(dir) => PathBuf::from(dir),
        None => PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../build/deps/wolfssl"),
    };
    let include = dir.join("include");
    let header = include.join("wolfssl/version.h");
    let text = std::fs::read_to_string(&header).unwrap_or_else(|e| {
        panic!(
            "{}: {e}: build wolfSSL with inventory/measure/deps.py, or name it in CURL_WOLFSSL_DIR",
            header.display()
        )
    });
    let version = text
        .lines()
        .find_map(|l| l.strip_prefix("#define LIBWOLFSSL_VERSION_STRING "))
        .map(|v| v.trim().trim_matches('"').to_owned())
        .expect("version.h names the version");
    let major: u32 = version
        .split('.')
        .next()
        .and_then(|m| m.parse().ok())
        .expect("a version's parts are numbers");
    if major < 5 {
        panic!("wolfSSL {version}: this build needs 5.0.0 or later");
    }
    // The hashes its configure left out, as C's build reads them
    // (`curl_md5.h`, `curl_sha256.h`, `curl_sha512_256.h`).
    let options = include.join("wolfssl/options.h");
    println!("cargo::rerun-if-changed={}", options.display());
    let options =
        std::fs::read_to_string(&options).unwrap_or_else(|e| panic!("{}: {e}", options.display()));
    for (define, cfg) in [
        ("NO_MD5", "no_md5"),
        ("NO_SHA256", "no_sha256"),
        ("WOLFSSL_NOSHA512_256", "no_sha512_256"),
    ] {
        println!("cargo::rustc-check-cfg=cfg({cfg})");
        if options
            .lines()
            .any(|l| l.split_whitespace().take(2).eq(["#define", define]))
        {
            println!("cargo::rustc-cfg={cfg}");
        }
    }
    let lib = dir.join("lib");
    println!(
        "cargo::rerun-if-changed={}",
        lib.join("libwolfssl.a").display()
    );
    println!("cargo::rustc-link-search=native={}", lib.display());
    println!("cargo::rustc-link-lib=static=wolfssl");
    // Its private libraries (wolfssl.pc's `Libs.private`).
    println!("cargo::rustc-link-lib=m");
    curl_build::write_ca_defaults();
    println!("cargo::rerun-if-changed=csrc/layout.c");
    cc::Build::new()
        .include(&include)
        // As CMake builds curl against it.
        .define("WOLFSSL_OPTIONS_IGNORE_SYS", None)
        .file("csrc/layout.c")
        .warnings_into_errors(true)
        .compile("curl_wolfssl_layout");
}
