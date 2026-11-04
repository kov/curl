//! The DLL names itself, and its import library names it, as C's CMake
//! build names libcurl: `libcurl-d.dll` for the debug build,
//! `libcurl.dll` otherwise. A program linked against the import library
//! loads the DLL by that name.

#![cfg(windows)]
// A test: aborting on a failed allocation is fine.
#![allow(clippy::disallowed_methods, clippy::disallowed_macros)]

/// The name C's build gives the DLL this build makes.
const NAME: &str = if cfg!(feature = "debug-hooks") {
    "libcurl-d.dll"
} else {
    "libcurl.dll"
};

/// The library cargo built beside this test, `curl.dll`, or its import
/// library. `cargo test` does not build a library that is only a
/// `cdylib`: one older than the build script's last run is refused, the
/// library to be built first (`cargo build -p curl-sys-abi`, with these
/// features).
fn built(file: &str) -> Vec<u8> {
    let exe = std::env::current_exe().unwrap();
    let path = exe.parent().unwrap().join(file);
    let modified = |p: &std::path::Path| {
        let m = std::fs::metadata(p).unwrap_or_else(|e| panic!("{}: {e}", p.display()));
        m.modified().unwrap()
    };
    let script = std::path::Path::new(env!("OUT_DIR")).join("libcurl.def");
    assert!(
        modified(&path) >= modified(&script),
        "{} is older than this build: build the library first",
        path.display()
    );
    std::fs::read(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

fn u16_at(b: &[u8], at: usize) -> usize {
    usize::from(u16::from_le_bytes([b[at], b[at + 1]]))
}

fn u32_at(b: &[u8], at: usize) -> usize {
    usize::try_from(u32::from_le_bytes([b[at], b[at + 1], b[at + 2], b[at + 3]])).unwrap()
}

/// The name in a PE image's export directory.
fn export_name(pe: &[u8]) -> String {
    let header = u32_at(pe, 0x3c);
    assert_eq!(&pe[header..header + 4], b"PE\0\0");
    let coff = header + 4;
    let sections = u16_at(pe, coff + 2);
    let optional = coff + 20;
    let optional_len = u16_at(pe, coff + 16);
    assert_eq!(u16_at(pe, optional), 0x20b, "PE32+");
    // The export table's directory entry, the first of PE32+'s.
    let exports = u32_at(pe, optional + 112);
    let to_file = |rva: usize| {
        let table = optional + optional_len;
        (0..sections)
            .map(|i| table + i * 40)
            .find_map(|s| {
                let (size, start, raw) =
                    (u32_at(pe, s + 8), u32_at(pe, s + 12), u32_at(pe, s + 20));
                (start..start + size)
                    .contains(&rva)
                    .then(|| rva - start + raw)
            })
            .expect("the address is in a section")
    };
    let name = to_file(u32_at(pe, to_file(exports) + 12));
    let end = pe[name..].iter().position(|&b| b == 0).unwrap();
    String::from_utf8(pe[name..name + end].to_vec()).unwrap()
}

#[test]
fn the_dll_is_named_as_c_s_build_names_it() {
    assert_eq!(export_name(&built("curl.dll")), NAME);
}

#[test]
fn the_import_library_names_the_dll_as_c_s_build_does() {
    let lib = built("curl.dll.lib");
    let names = |name: &[u8]| lib.windows(name.len()).filter(|w| *w == name).count();
    assert!(names(NAME.as_bytes()) > 0, "{NAME} not named");
    // Every mention of a DLL is of that one, none of cargo's `curl.dll`.
    assert_eq!(names(b".dll"), names(NAME.as_bytes()));
}
