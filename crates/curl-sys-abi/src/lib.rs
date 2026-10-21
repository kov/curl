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
#[allow(dead_code, reason = "the share and URL handles come later")]
mod error_codes;
#[cfg(feature = "debug-hooks")]
mod debug;

/// The debug test build tracks the shim's Rust allocations (`DESIGN.md`,
/// "Debug hooks").
#[cfg(feature = "debug-hooks")]
#[global_allocator]
static ALLOCATOR: curl_alloc::track::Tracker = curl_alloc::track::Tracker;
mod callbacks;
mod easy;
mod gate;
mod getinfo;
#[cfg(test)]
mod handle_tests;
mod multi;
mod printf;
mod root;
mod setopt;
mod strerror;
mod strings;
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
                    .take(4)
                    .find_map(|l| l.strip_prefix(name))
                    .map(str::to_owned)
            };
            let (Some(inputs), Some(recorded)) = (field("// inputs: "), field("// inputs-hash: "))
            else {
                continue;
            };
            let output =
                field("// output-hash: ").expect("generated files record their body's hash");
            let (_, body) = text.split_once("\n\n").expect("a header, then the body");
            assert_eq!(
                u64::from_str_radix(&output, 16).unwrap(),
                fnv1a(0xcbf2_9ce4_8422_2325, body.as_bytes()),
                "{} was edited by hand or reformatted: run gen/all.py",
                file.display()
            );
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

    /// Every sabotage entry's text must still be in the tree, once, or the
    /// sweep plants nothing (format in `sabotage/sweep.py`).
    #[test]
    fn sabotage_entries_are_current() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let mut checked = 0;
        for entry in std::fs::read_dir(root.join("sabotage/entries")).unwrap() {
            let path = entry.unwrap().path();
            if path.extension().is_none_or(|e| e != "txt") {
                continue;
            }
            let text = std::fs::read_to_string(&path).unwrap();
            for block in format!("\n{text}").split("\n=== ").skip(1) {
                let name = block.lines().next().unwrap();
                let file = block
                    .lines()
                    .find_map(|l| l.strip_prefix("file: "))
                    .unwrap_or_else(|| panic!("{}: '{name}' has no file:", path.display()));
                let (_, rest) = block
                    .split_once("\n--- old\n")
                    .unwrap_or_else(|| panic!("{}: '{name}' has no --- old", path.display()));
                let (old, _) = rest
                    .split_once("\n--- new")
                    .unwrap_or_else(|| panic!("{}: '{name}' has no --- new", path.display()));
                let source = std::fs::read_to_string(root.join(file)).unwrap_or_default();
                assert_eq!(
                    source.matches(old.trim_end_matches('\n')).count(),
                    1,
                    "{}: the text '{name}' changes is not in {file} exactly once",
                    path.display()
                );
                checked += 1;
            }
        }
        // A positive control: the walk must find the entries.
        assert!(checked >= 60, "found only {checked} entries");
    }
}
