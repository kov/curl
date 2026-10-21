//! Link libpsl, as the C build does.

fn main() {
    println!("cargo::rustc-link-lib=psl");
}
