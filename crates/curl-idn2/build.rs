//! Link libidn2, as the C build does, from where pkg-config finds it; with
//! the `apple-idn` feature the system's ICU and iconv instead, which the
//! code links by name (`USE_APPLE_IDN`).

// A build script is no library: the environment is read as cargo gives it.
#![allow(clippy::disallowed_methods)]

fn main() {
    if std::env::var_os("CARGO_FEATURE_APPLE_IDN").is_none() {
        curl_build::link("idn2", "libidn2");
    }
}
