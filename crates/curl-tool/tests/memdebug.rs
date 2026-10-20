//! Memory tracking in the tool, as the C suite's test 96 checks it for the
//! C tool. Test 96 matches the C tool's source file names in the memdump;
//! this checks the same property for ours: a memdump is written, it shows
//! the tool's allocations, and tests/memanalyze.pl, the analyser
//! runtests.pl uses, finds nothing wrong in it.

#![allow(clippy::disallowed_methods, clippy::disallowed_macros)]

use std::path::Path;
use std::process::Command;

#[test]
fn test96_memory_tracking_operational() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let memdump = std::env::temp_dir().join(format!("curl-tool-memdump-{}", std::process::id()));
    let out = Command::new(env!("CARGO_BIN_EXE_curl"))
        .arg("--version")
        .env("CURL_MEMDEBUG", &memdump)
        .env_remove("CURL_MEMLIMIT")
        .output()
        .unwrap();
    assert!(out.status.success(), "{out:?}");
    let log = std::fs::read_to_string(&memdump).unwrap_or_default();
    std::fs::remove_file(&memdump).ok();

    // The tool's allocations are there: without them a clean analysis
    // proves nothing.
    let allocations = log
        .lines()
        .filter(|l| l.starts_with("MEM rust:0 malloc("))
        .count();
    assert!(allocations > 0, "no allocations tracked:\n{log}");

    std::fs::write(&memdump, &log).unwrap();
    let analysis = Command::new("perl")
        .arg("-I")
        .arg(root.join("tests"))
        .arg(root.join("tests/memanalyze.pl"))
        .arg(&memdump)
        .output()
        .unwrap();
    std::fs::remove_file(&memdump).ok();
    assert!(analysis.status.success(), "{analysis:?}");
    let report = String::from_utf8_lossy(&analysis.stdout);
    assert!(
        report.is_empty(),
        "memanalyze.pl found problems:\n{report}\n{log}"
    );
}
