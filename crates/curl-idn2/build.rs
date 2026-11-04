//! Link libidn2, as the C build does, from where pkg-config finds it.

fn main() {
    curl_build::link("idn2", "libidn2");
}
