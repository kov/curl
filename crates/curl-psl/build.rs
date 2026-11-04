//! Link libpsl, as the C build does, from where pkg-config finds it.

fn main() {
    curl_build::link("psl", "libpsl");
}
