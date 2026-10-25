//! Link libnghttp2, as the C build does.

fn main() {
    println!("cargo::rustc-link-lib=nghttp2");
}
