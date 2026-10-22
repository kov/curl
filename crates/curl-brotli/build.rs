//! Link brotli's decoder, as the C build does.

fn main() {
    println!("cargo::rustc-link-lib=brotlidec");
}
