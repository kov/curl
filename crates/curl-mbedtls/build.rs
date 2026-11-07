//! Link mbedTLS, as the C build does, refusing a version before 3.2.0 as
//! C does (`mbedtls.c`'s `#error`) and one of 4.0 or later, whose calls
//! this binding does not make; decide where the library looks for
//! certificates to trust when a transfer names none, as CMake decides
//! it; and build the table of the headers' values and layouts
//! (`csrc/layout.c`), which also refuses a build of the library
//! configured otherwise than the binding follows.

// A build script is no library: aborting on a failed allocation is fine.
#![allow(clippy::disallowed_methods, clippy::disallowed_macros)]

fn main() {
    let version = curl_build::pkg_config("mbedtls", "--modversion")
        .and_then(|words| words.into_iter().next())
        .expect("pkg-config finds mbedTLS");
    let number: Vec<u32> = version
        .split('.')
        .map(|p| p.parse().expect("a version's parts are numbers"))
        .collect();
    if number.as_slice() < [3, 2, 0].as_slice() || number[0] >= 4 {
        panic!("mbedTLS {version}: this build needs 3.2.0 or later, before 4.0");
    }
    // 3.6.1 tells of TLS 1.3's tickets only where asked, which C asks
    // (`mbedtls_ssl_conf_tls13_enable_signal_new_session_tickets`).
    println!("cargo::rustc-check-cfg=cfg(mbedtls_signal_tickets)");
    if number.as_slice() >= [3, 6, 1].as_slice() {
        println!("cargo::rustc-cfg=mbedtls_signal_tickets");
    }
    curl_build::link("mbedtls", "mbedtls");
    curl_build::link("mbedx509", "mbedx509");
    curl_build::link("mbedcrypto", "mbedcrypto");
    curl_build::write_ca_defaults();
    println!("cargo::rerun-if-changed=csrc/layout.c");
    let mut build = cc::Build::new();
    for dir in curl_build::include_dirs("mbedtls") {
        build.include(dir);
    }
    build
        .file("csrc/layout.c")
        .warnings_into_errors(true)
        .compile("curl_mbedtls_layout");
}
