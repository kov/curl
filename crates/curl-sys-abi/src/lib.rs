//! libcurl's C ABI, translated onto `curl-core`.
//!
//! Everything C-shaped stops here: `CURLcode`, `long` options, varargs,
//! raw pointers and NUL-terminated strings are converted to and from the
//! Rust API at this boundary and go no further.

#![cfg_attr(all(feature = "nightly", target_arch = "aarch64"), feature(f128))]
// Tests may allocate infallibly; the non-test build is still checked.
#![cfg_attr(test, allow(clippy::disallowed_methods, clippy::disallowed_macros))]

#[rustfmt::skip]
mod ffi;
mod printf;
mod root;
mod version;

#[cfg(test)]
mod tests {
    /// `ffi.rs` must be regenerated whenever its inputs change.
    #[test]
    fn ffi_is_fresh() {
        let root = concat!(env!("CARGO_MANIFEST_DIR"), "/../..");
        let abi = std::fs::read(format!("{root}/inventory/abi.json")).unwrap();
        let generator = std::fs::read(format!("{root}/crates/curl-sys-abi/gen/ffi.py")).unwrap();
        let mut hash = 0xcbf2_9ce4_8422_2325_u64;
        let lines = abi.split_inclusive(|&b| b == b'\n');
        let abi = lines.filter(|line| !line.starts_with(b" \"c-commit\": "));
        for &b in abi.flatten().chain(&generator) {
            hash = (hash ^ u64::from(b)).wrapping_mul(0x0100_0000_01b3);
        }
        let recorded = include_str!("ffi.rs")
            .lines()
            .find_map(|l| l.strip_prefix("// inputs-hash: "))
            .expect("ffi.rs records its inputs hash");
        assert_eq!(
            u64::from_str_radix(recorded, 16).unwrap(),
            hash,
            "ffi.rs is stale: run crates/curl-sys-abi/gen/ffi.py"
        );
    }
}
