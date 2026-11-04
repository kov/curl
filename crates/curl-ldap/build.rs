//! Link libldap and liblber where libldap has `ldap_init_fd`, as the C
//! build takes OpenLDAP's backend only then (CMake's
//! `check_function_exists(ldap_init_fd)`, `USE_OPENLDAP`), and build the
//! table of their headers' values and layouts the tests compare
//! `src/sys.rs` with.

// A build script is no library: aborting on a failed allocation is fine.
#![allow(clippy::disallowed_methods, clippy::disallowed_macros)]

fn main() {
    println!("cargo::rustc-check-cfg=cfg(openldap)");
    // The core lists the LDAP protocols by the same answer.
    if !curl_build::openldap() {
        return;
    }
    println!("cargo::rustc-cfg=openldap");
    curl_build::link("ldap", "ldap");
    curl_build::link("lber", "lber");
    println!("cargo::rerun-if-changed=csrc/layout.c");
    let mut build = cc::Build::new();
    for dir in curl_build::include_dirs("ldap") {
        build.include(dir);
    }
    build
        .file("csrc/layout.c")
        .warnings_into_errors(true)
        .compile("curl_ldap_layout");
}
