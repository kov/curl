//! Link GnuTLS and nettle, as the C build does, refusing a GnuTLS older
//! than 3.6.5 as C does (`gtls.c`'s `#error`); decide where the library
//! looks for certificates to trust when a transfer names none, as CMake
//! decides it; and build the table of the headers' values the tests
//! compare `src/sys.rs` with.

// A build script is no library: aborting on a failed allocation is fine.
#![allow(clippy::disallowed_methods, clippy::disallowed_macros)]

fn main() {
    let version = curl_build::pkg_config("gnutls", "--modversion")
        .and_then(|words| words.into_iter().next())
        .expect("pkg-config finds GnuTLS");
    let number: Vec<u32> = version
        .split('.')
        .map(|p| p.parse().expect("a version's parts are numbers"))
        .collect();
    if number.as_slice() < [3, 6, 5].as_slice() {
        panic!("GnuTLS {version} is too old: this build needs 3.6.5 or later");
    }
    curl_build::link("gnutls", "gnutls");
    // Ed25519 is hogweed's; its hashes nettle's (CMake's FindNettle).
    curl_build::link("hogweed", "hogweed");
    curl_build::link("nettle", "nettle");
    curl_build::write_ca_defaults();
    println!("cargo::rerun-if-changed=csrc/layout.c");
    let mut build = cc::Build::new();
    for dir in curl_build::include_dirs("gnutls") {
        build.include(dir);
    }
    build
        .file("csrc/layout.c")
        .warnings_into_errors(true)
        .compile("curl_gnutls_layout");
}
