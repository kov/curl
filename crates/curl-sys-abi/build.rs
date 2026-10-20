//! Give the library the soname of the C build it replaces.

fn main() {
    let soname = if std::env::var_os("CARGO_FEATURE_DEBUG_HOOKS").is_some() {
        "libcurl-d.so.4"
    } else {
        "libcurl.so.4"
    };
    println!("cargo::rustc-cdylib-link-arg=-Wl,-soname,{soname}");
}
