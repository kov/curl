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
#[rustfmt::skip]
#[cfg_attr(
    not(test),
    expect(dead_code, reason = "the code mappings are unused until calls return errors")
)]
mod error_codes;
mod printf;
mod root;
mod strerror;
mod version;

#[cfg(test)]
mod tests {
    use std::path::{Path, PathBuf};

    fn fnv1a(hash: u64, bytes: &[u8]) -> u64 {
        bytes.iter().fold(hash, |h, &b| {
            (h ^ u64::from(b)).wrapping_mul(0x0100_0000_01b3)
        })
    }

    /// As `input_bytes` in `gen/genlib.py`.
    fn input_bytes(path: &Path) -> Vec<u8> {
        let data = std::fs::read(path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
        if path.extension().is_some_and(|e| e == "json") {
            let lines = data.split_inclusive(|&b| b == b'\n');
            return lines
                .filter(|l| !l.starts_with(b" \"c-commit\": "))
                .flatten()
                .copied()
                .collect();
        }
        data
    }

    fn rust_files(dir: &Path, out: &mut Vec<PathBuf>) {
        for entry in std::fs::read_dir(dir).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                rust_files(&path, out);
            } else if path.extension().is_some_and(|e| e == "rs") {
                out.push(path);
            }
        }
    }

    /// Every file a generator in `gen/` wrote must be regenerated when its
    /// inputs change.
    #[test]
    fn generated_is_fresh() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let mut files = Vec::new();
        rust_files(&root.join("crates"), &mut files);
        let mut checked = Vec::new();
        for file in files {
            let text = std::fs::read_to_string(&file).unwrap();
            let field = |name: &str| {
                text.lines()
                    .take(3)
                    .find_map(|l| l.strip_prefix(name))
                    .map(str::to_owned)
            };
            let (Some(inputs), Some(recorded)) = (field("// inputs: "), field("// inputs-hash: "))
            else {
                continue;
            };
            let hash = inputs.split(' ').fold(0xcbf2_9ce4_8422_2325, |h, input| {
                fnv1a(h, &input_bytes(&root.join(input)))
            });
            assert_eq!(
                u64::from_str_radix(&recorded, 16).unwrap(),
                hash,
                "{} is stale: run gen/all.py",
                file.display()
            );
            checked.push(file.file_name().unwrap().to_owned());
        }
        // A positive control: the walk must find the generated files.
        assert!(
            checked.iter().any(|f| f == "ffi.rs"),
            "found only {checked:?}"
        );
    }
}
