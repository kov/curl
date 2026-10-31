//! Link libldap and liblber, as the C build does, and build the table of
//! their headers' values and layouts the tests compare `src/sys.rs` with.

// A build script is no library: aborting on a failed allocation is fine.
#![allow(clippy::disallowed_methods)]

fn main() {
    println!("cargo::rustc-link-lib=ldap");
    println!("cargo::rustc-link-lib=lber");
    println!("cargo::rerun-if-changed=csrc/layout.c");
    cc::Build::new()
        .file("csrc/layout.c")
        .warnings_into_errors(true)
        .compile("curl_ldap_layout");
}
