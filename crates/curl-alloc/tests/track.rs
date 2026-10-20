//! Turning tracking on is process-wide, and past the limit every tracked
//! allocation fails, so this is its own test binary without the libtest
//! harness, and everything after the limit is spent runs untracked.

#![allow(clippy::disallowed_methods, clippy::disallowed_macros)]

use curl_alloc::track::{self, Tracker};
use curl_alloc::{TryArc, TryRc};

#[global_allocator]
static ALLOCATOR: Tracker = Tracker;

fn main() {
    logs_tracked_blocks_and_fails_past_the_limit();
    track::untracked(|| println!("track: ok"));
}

/// Blocks made before tracking or inside an exclusion are not logged;
/// tracked ones are, as tests/memanalyzer.pm reads them; the limit fails
/// fallible allocation without aborting.
fn logs_tracked_blocks_and_fails_past_the_limit() {
    let path = std::env::temp_dir().join(format!("curl-alloc-memdump-{}", std::process::id()));
    let before: Vec<u8> = Vec::with_capacity(100);
    track::start_log(&path).unwrap();
    let excluded: Vec<u8> = track::untracked(|| Vec::with_capacity(200));
    let mut tracked: Vec<u8> = Vec::with_capacity(300);
    let tracked_at = tracked.as_ptr();
    tracked.reserve(1000);
    let grown_at = tracked.as_ptr();
    drop((before, excluded, tracked));

    track::set_limit(1);
    let mut ok: Vec<u8> = Vec::new();
    assert!(ok.try_reserve(16).is_ok(), "the last allowed allocation");
    let mut refused: Vec<u8> = Vec::new();
    let refused = refused.try_reserve(16).is_err()
        && TryRc::try_new([0u8; 64]).is_err()
        && TryArc::try_new([0u8; 64]).is_err();
    track::untracked(|| check(&path, refused, [tracked_at, grown_at]));
    track::untracked(|| drop(ok));
}

/// `refused`: a `Vec`, a `TryRc` and a `TryArc` all failed past the limit.
fn check(path: &std::path::Path, refused: bool, [tracked_at, grown_at]: [*const u8; 2]) {
    assert!(refused, "past the limit");
    let log = std::fs::read_to_string(path).unwrap();
    std::fs::remove_file(path).unwrap();
    let want = [
        format!("MEM rust:0 malloc(300) = {tracked_at:p}"),
        format!("MEM rust:0 realloc({tracked_at:p}, 1000) = {grown_at:p}"),
        format!("MEM rust:0 free({grown_at:p})"),
        "LIMIT rust:0 malloc reached memlimit".to_owned(),
    ];
    for w in &want {
        assert!(log.lines().any(|l| l == w), "{w:?} not in\n{log}");
    }
    // As tests/memanalyzer.pm: every free names a block the log allocated.
    let mut live = std::collections::HashSet::new();
    for line in log.lines() {
        if let Some((_, block)) = line.split_once(") = ") {
            live.insert(block);
        } else if let Some(block) = line.strip_prefix("MEM rust:0 free(") {
            let block = block.trim_end_matches(')');
            assert!(
                live.remove(block),
                "free of an untracked block: {line}\n{log}"
            );
        }
    }
    for size in ["(100)", "(200)"] {
        assert!(!log.contains(size), "{size} is untracked:\n{log}");
    }
}
