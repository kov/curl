//! Link libnghttp2, as the C build does, from where pkg-config finds it.

fn main() {
    curl_build::link("nghttp2", "libnghttp2");
}
