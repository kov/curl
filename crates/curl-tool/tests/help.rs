//! The help the tool shows: `--help` and its topics, and the built-in
//! manual, all of it for `--manual` or one option's part.
//!
//! The expectations are the C tool's: `CURL_TOOL_UNDER_TEST` names
//! another tool to run them on, as
//! `CURL_TOOL_UNDER_TEST=build/c/src/curl LD_LIBRARY_PATH=build/c/lib`.

#![allow(clippy::disallowed_methods)]

use std::path::PathBuf;
use std::process::Command;

struct Run {
    code: i32,
    stdout: String,
    stderr: String,
}

/// Run the tool with `args`, without a configuration file.
fn curl(args: &[&str]) -> Run {
    let tool = std::env::var_os("CURL_TOOL_UNDER_TEST")
        .map_or_else(|| PathBuf::from(env!("CARGO_BIN_EXE_curl")), PathBuf::from);
    let out = Command::new(tool).arg("-q").args(args).output().unwrap();
    Run {
        code: out.status.code().unwrap(),
        stdout: String::from_utf8(out.stdout).unwrap(),
        stderr: String::from_utf8(out.stderr).unwrap(),
    }
}

/// `--help` alone shows the important options; with an option, that
/// option's text from the manual, up to the next option's; with one
/// the manual lacks, a complaint.
#[test]
fn shows_help_on_what_is_asked() {
    let run = curl(&["--help"]);
    assert_eq!(run.code, 0, "{}", run.stderr);
    assert!(
        run.stdout
            .starts_with("Usage: curl [options...] <url>\n -d, --data <data> "),
        "{}",
        run.stdout
    );
    assert!(
        run.stdout
            .contains("\nUse \"--help all\" to list all options\n")
    );

    let run = curl(&["--help", "-v"]);
    assert_eq!(run.code, 0, "{}", run.stderr);
    assert!(
        run.stdout.starts_with("    -v, --verbose\n"),
        "{}",
        run.stdout
    );
    assert!(run.stdout.contains("Make curl output verbose"));
    assert!(run.stdout.contains("--trace and --trace-ascii.\n"));
    assert!(!run.stdout.contains("    -V, --version"), "{}", run.stdout);

    let run = curl(&["--help", "--nosuchoption"]);
    assert_eq!(run.code, 0);
    assert_eq!(run.stdout, "");
    assert_eq!(
        run.stderr,
        "Incorrect option name to show help for, see curl -h\n"
    );
}

/// `--manual` shows the whole manual.
#[test]
fn shows_the_manual() {
    let run = curl(&["--manual"]);
    assert_eq!(run.code, 0, "{}", run.stderr);
    assert!(run.stdout.len() > 200_000, "{}", run.stdout.len());
    assert!(run.stdout.contains("\nALL OPTIONS\n"));
    assert!(run.stdout.contains("\n    -v, --verbose\n"));
    assert!(run.stdout.contains("\nFILES\n"));
}
