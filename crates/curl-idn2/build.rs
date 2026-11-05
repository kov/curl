//! Choose the IDN library, once, for the code and the link alike: on
//! Windows its own conversions (`USE_WIN32_IDN`, cfg `win_idn`), as both
//! reference Windows builds have them, which windows-sys links from
//! `normaliz`, unless the `libidn2` feature asks for libidn2 there; with
//! the `apple-idn` feature the system's ICU and iconv (`USE_APPLE_IDN`,
//! cfg `apple_idn`), which the code links by name; elsewhere libidn2, as
//! the C build has it, from where pkg-config finds it.

// A build script is no library: the environment is read as cargo gives it.
#![allow(clippy::disallowed_methods)]

use std::env;

fn main() {
    println!("cargo::rustc-check-cfg=cfg(win_idn)");
    println!("cargo::rustc-check-cfg=cfg(apple_idn)");
    let feature = |name: &str| env::var_os(name).is_some();
    let windows = env::var("CARGO_CFG_TARGET_OS").is_ok_and(|os| os == "windows");
    let (win_idn, apple_idn, libidn2) = (
        feature("CARGO_FEATURE_WIN_IDN"),
        feature("CARGO_FEATURE_APPLE_IDN"),
        feature("CARGO_FEATURE_LIBIDN2"),
    );
    let chosen = [win_idn, apple_idn, libidn2].iter().filter(|&&f| f).count();
    assert!(
        chosen <= 1,
        "one IDN library at a time: `win-idn`, `apple-idn` or `libidn2`"
    );
    assert!(
        windows || !win_idn,
        "`win-idn` is Windows' own IDN conversion, built only for Windows"
    );
    assert!(
        !windows || !apple_idn,
        "`apple-idn` is Apple's own IDN conversion, not built for Windows"
    );
    if windows && !libidn2 {
        println!("cargo::rustc-cfg=win_idn");
    } else if apple_idn {
        println!("cargo::rustc-cfg=apple_idn");
    } else {
        curl_build::link("idn2", "libidn2");
    }
}
