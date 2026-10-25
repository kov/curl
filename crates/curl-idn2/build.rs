//! Link libidn2, as the C build does.

fn main() {
    println!("cargo::rustc-link-lib=idn2");
}
