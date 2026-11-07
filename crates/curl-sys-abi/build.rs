//! Give the library the soname of the C build it replaces, build the C
//! helper that reads `long double` arguments on stable Rust, and say
//! whether the OpenSSL linked is LibreSSL (`cfg(libressl)`) or AWS-LC or
//! BoringSSL (`cfg(boringssl_like)`), as openssl-sys reports it.

// A build script is no library: aborting on a failed allocation is fine.
#![allow(clippy::disallowed_methods, clippy::disallowed_macros)]

fn main() {
    println!("cargo::rerun-if-env-changed=DEP_OPENSSL_LIBRESSL_VERSION_NUMBER");
    println!("cargo::rustc-check-cfg=cfg(libressl)");
    if std::env::var_os("DEP_OPENSSL_LIBRESSL_VERSION_NUMBER").is_some() {
        println!("cargo::rustc-cfg=libressl");
    }
    // AWS-LC or BoringSSL (`HAVE_BORINGSSL_LIKE`).
    println!("cargo::rerun-if-env-changed=DEP_OPENSSL_AWSLC");
    println!("cargo::rerun-if-env-changed=DEP_OPENSSL_BORINGSSL");
    println!("cargo::rustc-check-cfg=cfg(boringssl_like)");
    if ["DEP_OPENSSL_AWSLC", "DEP_OPENSSL_BORINGSSL"]
        .iter()
        .any(|v| std::env::var(v).as_deref() == Ok("true"))
    {
        println!("cargo::rustc-cfg=boringssl_like");
    }
    let debug = std::env::var_os("CARGO_FEATURE_DEBUG_HOOKS").is_some();
    // Windows has no soname: a program names the DLL's file, which the
    // build tree lays out as C's CMake names it (`libcurl-d.dll`). macOS's
    // is the install name, C's CMake's `@rpath/libcurl.4.dylib`.
    let os = std::env::var("CARGO_CFG_TARGET_OS");
    if os.as_deref() == Ok("macos") {
        let name = if debug {
            "@rpath/libcurl-d.4.dylib"
        } else {
            "@rpath/libcurl.4.dylib"
        };
        println!("cargo::rustc-cdylib-link-arg=-Wl,-install_name,{name}");
    } else if os.as_deref() != Ok("windows") {
        let soname = if debug {
            "libcurl-d.so.4"
        } else {
            "libcurl.so.4"
        };
        println!("cargo::rustc-cdylib-link-arg=-Wl,-soname,{soname}");
    }
    // The library and the tool are both `curl`, and on Windows each would
    // write its debug information to `curl.pdb` beside the other: the
    // library's goes where this script's output does.
    if std::env::var("CARGO_CFG_TARGET_ENV").as_deref() == Ok("msvc") {
        let out = std::env::var("OUT_DIR").expect("cargo sets OUT_DIR");
        println!("cargo::rustc-cdylib-link-arg=/PDB:{out}\\libcurl.pdb");
        // The DLL names itself, and its import library names it, as C's
        // CMake build names libcurl, whatever file cargo writes it to
        // (`curl.dll`): a program linked against the import library loads
        // it by that name. The linker takes the name from a second module
        // definition, beside rustc's list of exports, and warns that it is
        // not the file's (LNK4070), which is the point.
        let name = if debug { "libcurl-d" } else { "libcurl" };
        let def = format!("{out}\\libcurl.def");
        std::fs::write(&def, format!("LIBRARY {name}\r\n")).expect("OUT_DIR is writable");
        println!("cargo::rustc-cdylib-link-arg=/DEF:{def}");
        println!("cargo::rustc-cdylib-link-arg=/IGNORE:4070");
    }
    // The debug test build links the debug C library, as C's debug build
    // does (`/MDd`): the streams, memory and `errno` a test program hands
    // over are that library's, and a stream written here must be the
    // program's own, buffer and all.
    if debug && std::env::var("CARGO_CFG_TARGET_ENV").as_deref() == Ok("msvc") {
        for lib in ["msvcrt", "vcruntime", "ucrt"] {
            println!("cargo::rustc-cdylib-link-arg=/NODEFAULTLIB:{lib}.lib");
        }
        for lib in ["msvcrtd", "vcruntimed", "ucrtd"] {
            println!("cargo::rustc-cdylib-link-arg=/DEFAULTLIB:{lib}.lib");
        }
    }
    println!("cargo::rerun-if-changed=csrc/va_fetch.c");
    cc::Build::new()
        .file("csrc/va_fetch.c")
        .warnings_into_errors(true)
        .compile("curl_rs_va_fetch");
}
