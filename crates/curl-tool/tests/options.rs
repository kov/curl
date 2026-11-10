//! Options as C's tool takes them, seen from outside: what it says, how
//! it ends and what `--libcurl` writes, with no transfer made (`--proto
//! =file` refuses the URL once the transfer is set up).
//!
//! The expectations are the C tool's: `CURL_TOOL_UNDER_TEST` names
//! another tool to run them on, as
//! `CURL_TOOL_UNDER_TEST=build/c/src/curl LD_LIBRARY_PATH=build/c/lib`.

#![allow(clippy::disallowed_methods, clippy::disallowed_macros)]

use std::path::PathBuf;
use std::process::Command;

const URL: &str = "http://127.0.0.1:1/x";

/// A directory of its own for a test, removed after it.
struct Scratch(PathBuf);

impl Scratch {
    fn new(name: &str) -> Scratch {
        let dir = std::env::temp_dir().join(format!("curl-tool-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir(&dir).unwrap();
        Scratch(dir)
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.0).unwrap();
    }
}

struct Run {
    code: i32,
    stdout: String,
    stderr: String,
    /// What `--libcurl` wrote.
    source: String,
}

/// Run the tool in `dir` with `args`, then `--libcurl`, `--proto =file`
/// and `URL`, without a configuration file.
fn curl(dir: &Scratch, args: &[&str]) -> Run {
    let tool = std::env::var_os("CURL_TOOL_UNDER_TEST")
        .map_or_else(|| PathBuf::from(env!("CARGO_BIN_EXE_curl")), PathBuf::from);
    let source = dir.0.join("source.c");
    let _ = std::fs::remove_file(&source);
    // Without the CA path cargo hands its children (`SSL_CERT_DIR`): a
    // library without CA paths warns of it, as C's tool does.
    let out = Command::new(tool)
        .env_remove("SSL_CERT_DIR")
        .arg("-q")
        .args(args)
        .args(["--libcurl", "source.c", "--proto", "=file", URL])
        .current_dir(&dir.0)
        .output()
        .unwrap();
    Run {
        code: out.status.code().unwrap(),
        stdout: String::from_utf8(out.stdout).unwrap().replace("\r\n", "\n"),
        stderr: String::from_utf8(out.stderr).unwrap().replace("\r\n", "\n"),
        source: std::fs::read_to_string(&source).unwrap(),
    }
}

const REFUSED: &str = "curl: (1) Protocol \"http\" is disabled\n";

/// `--false-start` is still a boolean, so `--no-false-start` is taken
/// too, and either is warned of as deprecated and does nothing more.
#[test]
fn false_start_is_warned_of_and_does_nothing() {
    let dir = Scratch::new("false-start");
    for flag in ["--false-start", "--no-false-start"] {
        let run = curl(&dir, &[flag]);
        assert_eq!(run.code, 1, "{flag}");
        assert_eq!(
            run.stderr,
            format!("Warning: --false-start is deprecated and has no function anymore\n{REFUSED}"),
            "{flag}"
        );
        assert!(run.source.contains("CURLOPT_URL"), "{flag}: {}", run.source);
    }
}

/// `--remote-header-name` keeps the proxy's CONNECT response from the
/// headers it reads the name from, and `--no-remote-header-name` lets it
/// through again, whichever of it and `--suppress-connect-headers` came
/// last deciding.
#[test]
fn remote_header_name_suppresses_connect_headers() {
    let dir = Scratch::new("remote-header-name");
    let line = "curl_easy_setopt(curl, CURLOPT_SUPPRESS_CONNECT_HEADERS, 1L);";
    for (args, suppressed) in [
        (&["-J", "-O"][..], true),
        (
            &[
                "--suppress-connect-headers",
                "-J",
                "-O",
                "--no-remote-header-name",
            ][..],
            false,
        ),
        (
            &[
                "-J",
                "-O",
                "--no-remote-header-name",
                "--suppress-connect-headers",
            ][..],
            true,
        ),
        (&["-O"][..], false),
    ] {
        let run = curl(&dir, args);
        assert_eq!(run.code, 1, "{args:?}");
        assert_eq!(run.stderr, REFUSED, "{args:?}");
        assert_eq!(
            run.source.contains(line),
            suppressed,
            "{args:?}: {}",
            run.source
        );
    }
}

/// A `--time-cond` that is neither a date nor a file leaves no condition,
/// but the time beside it is the -1 the date failed to read as.
#[test]
fn an_unreadable_time_condition_keeps_its_time() {
    let dir = Scratch::new("time-cond");
    let run = curl(&dir, &["-z", "dec 12 12:00:00 1999 GMT", "-z", "bogus"]);
    assert_eq!(run.code, 1);
    assert!(run.stderr.ends_with(REFUSED), "{}", run.stderr);
    assert!(
        run.source
            .contains("curl_easy_setopt(curl, CURLOPT_TIMEVALUE_LARGE, (curl_off_t)-1);"),
        "{}",
        run.source
    );
    assert!(
        !run.source.contains("CURLOPT_TIMECONDITION"),
        "{}",
        run.source
    );
    let run = curl(&dir, &["-z", "dec 12 12:00:00 1999 GMT"]);
    assert!(
        run.source
            .contains("curl_easy_setopt(curl, CURLOPT_TIMEVALUE_LARGE, (curl_off_t)945000000);"),
        "{}",
        run.source
    );
}

/// A transfer whose setup fails stops at the option that fails, the
/// calls before it written and none after, and is a transfer still,
/// whose `--write-out` is written: data to send with a resume refused
/// where it is set, a form's file that cannot be read failing it at
/// `CURLOPT_MIMEPOST`, before `CURLOPT_INTERFACE`'s refusal of a
/// malformed interface would.
#[test]
fn a_setup_stops_at_the_option_that_fails() {
    let dir = Scratch::new("setup-fails");
    let unresumed = "curl: (43) HTTP upload cannot be resumed\n";
    for data in [["-d", "a=b"], ["-F", "a=b"]] {
        let run = curl(&dir, &["-C", "10", data[0], data[1], "-w", "%{exitcode}"]);
        assert_eq!((run.code, run.stderr.as_str()), (43, unresumed), "{data:?}");
        assert_eq!(run.stdout, "43", "{data:?}");
        assert!(run.source.contains("CURLOPT_USERAGENT"), "{}", run.source);
        assert!(!run.source.contains("CURLOPT_POST"), "{}", run.source);
        assert!(!run.source.contains("CURLOPT_MIMEPOST"), "{}", run.source);
    }
    let unreadable = "curl: (26) Failed to open/read local data from file/application\n";
    let run = curl(&dir, &["-F", "a=@missing"]);
    assert_eq!((run.code, run.stderr.as_str()), (26, unreadable));
    assert!(run.source.contains("CURLOPT_URL"), "{}", run.source);
    assert!(run.source.contains("CURLOPT_USERAGENT"), "{}", run.source);
    assert!(!run.source.contains("CURLOPT_MIMEPOST"), "{}", run.source);
    assert!(!run.source.contains("CURLOPT_MAXREDIRS"), "{}", run.source);
    let run = curl(&dir, &["--interface", "if!", "-F", "a=@missing"]);
    assert_eq!((run.code, run.stderr.as_str()), (26, unreadable));
    let run = curl(&dir, &["--interface", "if!"]);
    assert_eq!(
        (run.code, run.stderr.as_str()),
        (43, "curl: (43) setopt 0x274e got bad argument\n")
    );
    assert!(run.source.contains("CURLOPT_MAXREDIRS"), "{}", run.source);
    assert!(!run.source.contains("CURLOPT_INTERFACE"), "{}", run.source);
}
