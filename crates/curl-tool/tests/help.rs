//! The help the tool shows: `--help` and its topics, and the built-in
//! manual, all of it for `--manual` or one option's part.
//!
//! The expectations are the C tool's: `CURL_TOOL_UNDER_TEST` names
//! another tool to run them on, as
//! `CURL_TOOL_UNDER_TEST=build/c/src/curl LD_LIBRARY_PATH=build/c/lib`.

#![allow(clippy::disallowed_methods, clippy::disallowed_macros)]

use std::path::PathBuf;
use std::process::Command;

struct Run {
    code: i32,
    /// What went to standard output, as `text` reads it.
    stdout: String,
    /// What went to standard output, byte for byte.
    out: Vec<u8>,
    /// What went to standard error, as `text` reads it.
    stderr: String,
}

/// Text the tool wrote through the C library's text mode, as C's
/// `printf` writes to `stdout` and `stderr`: on Windows, where text mode
/// writes a carriage return before each line feed, each such pair is read
/// as its line feed.
fn text(bytes: &[u8]) -> String {
    let text = String::from_utf8(bytes.to_owned()).unwrap();
    if cfg!(windows) {
        text.replace("\r\n", "\n")
    } else {
        text
    }
}

/// Run the tool with `args`, without a configuration file.
fn curl(args: &[&str]) -> Run {
    let tool = std::env::var_os("CURL_TOOL_UNDER_TEST")
        .map_or_else(|| PathBuf::from(env!("CARGO_BIN_EXE_curl")), PathBuf::from);
    let out = Command::new(tool).arg("-q").args(args).output().unwrap();
    Run {
        code: out.status.code().unwrap(),
        stdout: text(&out.stdout),
        out: out.stdout,
        stderr: text(&out.stderr),
    }
}

/// Whether `bytes` has a line feed with no carriage return before it.
fn has_bare_line_feed(bytes: &[u8]) -> bool {
    bytes.starts_with(b"\n") || bytes.windows(2).any(|w| w[1] == b'\n' && w[0] != b'\r')
}

/// The help, the manual and the version go to standard output in text
/// mode, as C's `printf` and `puts` write them: on Windows each line ends
/// in CR LF.
#[test]
fn writes_help_as_text() {
    let eol = if cfg!(windows) { "\r\n" } else { "\n" };
    for (args, first) in [
        (&["--help"][..], "Usage: curl [options...] <url>"),
        (&["--help", "-v"], "    -v, --verbose"),
        (
            &["--help", "category"],
            " auth        Authentication methods",
        ),
        (&["-V"], "curl "),
        (&["--manual"], ""),
    ] {
        let run = curl(args);
        assert_eq!(run.code, 0, "{args:?}: {}", run.stderr);
        let out = String::from_utf8(run.out).unwrap();
        let line = out.split_inclusive('\n').next().unwrap();
        assert!(line.starts_with(first), "{args:?}: {line:?}");
        assert!(line.ends_with(eol), "{args:?}: {line:?}");
        assert_eq!(
            has_bare_line_feed(out.as_bytes()),
            !cfg!(windows),
            "{args:?}"
        );
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

/// `curl -V` into a pipe whose reader is gone, as `curl -V | head -1`
/// can leave it, ends quietly with 0, as C's unchecked `printf`s do,
/// instead of panicking on the failed write.
#[test]
fn a_version_listing_into_a_closed_pipe_ends_quietly() {
    let tool = std::env::var_os("CURL_TOOL_UNDER_TEST")
        .map_or_else(|| PathBuf::from(env!("CARGO_BIN_EXE_curl")), PathBuf::from);
    let (reader, writer) = std::io::pipe().unwrap();
    drop(reader);
    let out = Command::new(tool)
        .args(["-q", "-V"])
        .stdout(writer)
        .output()
        .unwrap();
    let stderr = String::from_utf8(out.stderr).unwrap();
    assert_eq!(out.status.code(), Some(0), "{stderr}");
    assert!(!stderr.contains("panicked"), "{stderr}");
}

/// Without a resolver that can take them, the DNS options are refused as
/// C's threaded build refuses them.
#[test]
fn the_dns_options_need_a_library_that_has_them() {
    // A build with c-ares takes them.
    if !cfg!(feature = "threaded-resolver") {
        return;
    }
    for (option, value) in [
        ("--dns-servers", "127.0.0.1"),
        ("--dns-interface", "lo"),
        ("--dns-ipv4-addr", "127.0.0.1"),
        ("--dns-ipv6-addr", "::1"),
    ] {
        let run = curl(&[option, value, "http://127.0.0.1:1/"]);
        assert_eq!(run.code, 2, "{option}");
        assert!(
            run.stderr.starts_with(&format!(
                "curl: option {option}: the installed libcurl version does not support this\n"
            )),
            "{}",
            run.stderr
        );
    }
}
