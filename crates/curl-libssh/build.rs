//! Link libssh, as the C build does, and build the table of its headers'
//! values and layouts the tests compare `src/sys.rs` with.

// A build script is no library: aborting on a failed allocation is fine.
#![allow(clippy::disallowed_methods, clippy::disallowed_macros)]

fn main() {
    // Where libssh is not in the compiler's own paths (Homebrew's on
    // macOS), from pkg-config, as CMake's FindLibssh takes it. MSVC
    // finds vcpkg's through its own environment.
    curl_build::link("ssh", "libssh");
    println!("cargo::rerun-if-changed=csrc/layout.c");
    let mut build = cc::Build::new();
    for dir in curl_build::include_dirs("libssh") {
        build.include(dir);
    }
    // MSVC's C knows `_Static_assert` from C11 on, which it is not in
    // unless asked.
    if std::env::var("CARGO_CFG_TARGET_ENV").is_ok_and(|e| e == "msvc") {
        build.std("c11");
    }
    build
        .file("csrc/layout.c")
        .warnings_into_errors(true)
        .compile("curl_libssh_layout");
}
