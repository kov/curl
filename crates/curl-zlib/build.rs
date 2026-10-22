//! Link zlib, as the C build does.

fn main() {
    println!("cargo::rustc-link-lib=z");
}
