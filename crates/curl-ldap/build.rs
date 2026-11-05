//! Link libldap and liblber where they link, and say which way C's build
//! drives them: over the connection's socket where libldap has
//! `ldap_init_fd` (`lib/openldap.c`, `USE_OPENLDAP`), over a connection
//! of its own where it has not, as macOS's LDAP.framework (`lib/ldap.c`);
//! none on Windows, whose WinLDAP windows-sys links; and build the table of their headers' values and layouts the tests
//! compare `src/sys.rs` with.

// A build script is no library: aborting on a failed allocation is fine.
#![allow(clippy::disallowed_methods, clippy::disallowed_macros)]

fn main() {
    println!("cargo::rustc-check-cfg=cfg(openldap)");
    println!("cargo::rustc-check-cfg=cfg(ldap)");
    // Windows' WinLDAP is the system's, linked by windows-sys.
    if std::env::var("CARGO_CFG_TARGET_OS").is_ok_and(|os| os == "windows") {
        return;
    }
    // The core lists the LDAP protocols by the same answer.
    let ldap = curl_build::ldap();
    if !ldap.links {
        return;
    }
    // The way of `lib/ldap.c` builds wherever the library links, so its
    // binding is tested on every build; it is the one used where libldap
    // has no `ldap_init_fd`.
    println!("cargo::rustc-cfg=ldap");
    if ldap.init_fd {
        println!("cargo::rustc-cfg=openldap");
    }
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
