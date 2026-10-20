//! Give the library the soname of the C build it replaces, and build the
//! C helper that reads `long double` arguments on stable Rust.

fn main() {
    let soname = if std::env::var_os("CARGO_FEATURE_DEBUG_HOOKS").is_some() {
        "libcurl-d.so.4"
    } else {
        "libcurl.so.4"
    };
    println!("cargo::rustc-cdylib-link-arg=-Wl,-soname,{soname}");
    println!("cargo::rerun-if-changed=csrc/va_fetch.c");
    cc::Build::new()
        .file("csrc/va_fetch.c")
        .warnings_into_errors(true)
        .compile("curl_rs_va_fetch");
}
