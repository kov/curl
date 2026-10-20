//! Take the version from `include/curl/curlver.h`, the one place it is set.

#![allow(clippy::disallowed_methods, clippy::disallowed_macros)]

use std::{env, fs, path::Path};

fn define<'a>(header: &'a str, name: &str) -> &'a str {
    header
        .lines()
        .find_map(|l| l.strip_prefix(&format!("#define {name} ")))
        .unwrap_or_else(|| panic!("curlver.h does not define {name}"))
        .trim()
}

fn string(header: &str, name: &str) -> String {
    let v = define(header, name);
    let s = v
        .strip_prefix('"')
        .and_then(|v| v.strip_suffix('"'))
        .unwrap_or_else(|| panic!("{name} is not a string: {v}"));
    assert!(!s.contains(['\\', '"']), "{name} needs escaping: {s}");
    s.to_owned()
}

fn number(header: &str, name: &str) -> u8 {
    define(header, name)
        .parse()
        .unwrap_or_else(|e| panic!("{name}: {e}"))
}

fn main() {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../include/curl/curlver.h");
    println!("cargo::rerun-if-changed={}", path.display());
    let header = fs::read_to_string(&path).expect("read curlver.h");
    let out = format!(
        "pub(crate) const VERSION: &str = {:?};\n\
         pub(crate) const MAJOR: u8 = {};\n\
         pub(crate) const MINOR: u8 = {};\n\
         pub(crate) const PATCH: u8 = {};\n\
         pub(crate) const TIMESTAMP: &str = {:?};\n",
        string(&header, "LIBCURL_VERSION"),
        number(&header, "LIBCURL_VERSION_MAJOR"),
        number(&header, "LIBCURL_VERSION_MINOR"),
        number(&header, "LIBCURL_VERSION_PATCH"),
        string(&header, "LIBCURL_TIMESTAMP"),
    );
    let dest = Path::new(&env::var("OUT_DIR").unwrap()).join("curlver.rs");
    fs::write(dest, out).expect("write curlver.rs");
}
