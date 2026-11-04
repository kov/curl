//! Link libssh, as the C build does, and build the table of its headers'
//! values and layouts the tests compare `src/sys.rs` with.

// A build script is no library: aborting on a failed allocation is fine.
#![allow(clippy::disallowed_methods)]

use std::process::Command;

fn main() {
    println!("cargo::rustc-link-lib=ssh");
    println!("cargo::rerun-if-changed=csrc/layout.c");
    println!("cargo::rerun-if-env-changed=PKG_CONFIG_PATH");
    let mut build = cc::Build::new();
    // Where libssh is not in the compiler's own paths (Homebrew's on
    // macOS), take them from pkg-config, as CMake's FindLibssh does. MSVC
    // finds vcpkg's through its own environment.
    let msvc = std::env::var("CARGO_CFG_TARGET_ENV").is_ok_and(|e| e == "msvc");
    for (flag, prefix) in [("--cflags-only-I", "-I"), ("--libs-only-L", "-L")] {
        if msvc {
            break;
        }
        let Ok(out) = Command::new("pkg-config").args([flag, "libssh"]).output() else {
            break;
        };
        if !out.status.success() {
            break;
        }
        let text = String::from_utf8(out.stdout).expect("pkg-config's output is text");
        for dir in text
            .split_whitespace()
            .filter_map(|w| w.strip_prefix(prefix))
        {
            if prefix == "-I" {
                build.include(dir);
            } else {
                println!("cargo::rustc-link-search=native={dir}");
            }
        }
    }
    // MSVC's C knows `_Static_assert` from C11 on, which it is not in
    // unless asked.
    if msvc {
        build.std("c11");
    }
    build
        .file("csrc/layout.c")
        .warnings_into_errors(true)
        .compile("curl_libssh_layout");
}
