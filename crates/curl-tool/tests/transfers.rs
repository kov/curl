//! The tool running `file://` transfers: output files, headers, resuming,
//! uploads, skipping, `--write-out` and how results are reported.
//!
//! The expectations are the C tool's: `CURL_TOOL_UNDER_TEST` names
//! another tool to run them on, as
//! `CURL_TOOL_UNDER_TEST=build/c/src/curl LD_LIBRARY_PATH=build/c/lib`.

#![allow(clippy::disallowed_methods, clippy::disallowed_macros)]

use std::os::unix::fs::MetadataExt as _;
use std::path::PathBuf;
use std::process::Command;
use std::time::{Duration, SystemTime};

/// A directory of its own for a test, removed after it.
struct Scratch(PathBuf);

impl Scratch {
    fn new(name: &str) -> Scratch {
        let dir = std::env::temp_dir().join(format!("curl-tool-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir(&dir).unwrap();
        Scratch(dir)
    }

    fn path(&self, name: &str) -> String {
        self.0.join(name).to_str().unwrap().to_owned()
    }

    fn url(&self, name: &str) -> String {
        format!("file://{}", self.path(name))
    }

    fn write(&self, name: &str, content: &[u8]) {
        std::fs::write(self.0.join(name), content).unwrap();
    }

    fn read(&self, name: &str) -> Vec<u8> {
        std::fs::read(self.0.join(name)).unwrap()
    }

    fn exists(&self, name: &str) -> bool {
        self.0.join(name).exists()
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.0).unwrap();
    }
}

struct Run {
    code: i32,
    stdout: Vec<u8>,
    stderr: String,
}

/// Run the tool with `args`, in `dir`, without a configuration file.
fn curl(dir: &Scratch, args: &[&str]) -> Run {
    curl_env(dir, args, &[])
}

fn curl_env(dir: &Scratch, args: &[&str], env: &[(&str, &str)]) -> Run {
    let tool = std::env::var_os("CURL_TOOL_UNDER_TEST")
        .map_or_else(|| PathBuf::from(env!("CARGO_BIN_EXE_curl")), PathBuf::from);
    let out = Command::new(tool)
        .arg("-q")
        .args(args)
        .current_dir(&dir.0)
        .envs(env.iter().copied())
        .output()
        .unwrap();
    Run {
        code: out.status.code().unwrap(),
        stdout: out.stdout,
        stderr: String::from_utf8(out.stderr).unwrap(),
    }
}

#[test]
fn downloads_to_a_file_or_standard_output() {
    let s = Scratch::new("download");
    s.write("f", b"hello\n");
    let r = curl(&s, &["-s", "-o", "out", &s.url("f")]);
    assert_eq!((r.code, &r.stdout[..], &r.stderr[..]), (0, &b""[..], ""));
    assert_eq!(s.read("out"), b"hello\n");
    // Two URLs to standard output, one after the other (test 202).
    let r = curl(&s, &["-s", &s.url("f"), &s.url("f")]);
    assert_eq!(r.stdout, b"hello\nhello\n");
    // `--out-null` writes nothing anywhere.
    let r = curl(&s, &["-s", "--out-null", &s.url("f")]);
    assert_eq!((r.code, &r.stdout[..]), (0, &b""[..]));
}

/// A successful transfer that wrote nothing still leaves its output
/// file, empty (`post_output_handling`); a failed one leaves none.
#[test]
fn an_empty_download_leaves_an_empty_file() {
    let s = Scratch::new("empty");
    s.write("f", b"");
    let r = curl(&s, &["-s", "-o", "out", &s.url("f")]);
    assert_eq!(r.code, 0);
    assert_eq!(s.read("out"), b"");
    let r = curl(&s, &["-s", "-o", "none", &s.url("missing")]);
    assert_eq!(r.code, 37);
    assert!(!s.exists("none"));
}

/// The result line, muted by `--silent` unless `--show-error`.
#[test]
fn reports_a_failure() {
    let s = Scratch::new("failure");
    let r = curl(&s, &[&s.url("missing")]);
    assert_eq!(r.code, 37);
    assert!(r.stderr.starts_with("curl: (37) "), "{:?}", r.stderr);
    assert!(r.stderr.ends_with('\n'), "{:?}", r.stderr);
    let r = curl(&s, &["-s", &s.url("missing")]);
    assert_eq!((r.code, &r.stderr[..]), (37, ""));
    let r = curl(&s, &["-sS", &s.url("missing")]);
    assert!(r.stderr.starts_with("curl: (37) "), "{:?}", r.stderr);
    // `%{onerror}` ends the output of a transfer that succeeded.
    s.write("f", b"x");
    let r = curl(&s, &["-s", "-o", "o", "-w", "a%{onerror}b", &s.url("f")]);
    assert_eq!(r.stdout, b"a");
    let r = curl(&s, &["-s", "-w", "a%{onerror}b", &s.url("missing")]);
    assert_eq!(r.stdout, b"ab");
    // The last transfer's result is the exit status.
    s.write("f", b"x");
    let r = curl(&s, &["-s", &s.url("missing"), &s.url("f")]);
    assert_eq!(r.code, 0);
}

/// `--include` writes a file's header lines before its body.
#[test]
fn includes_headers() {
    let s = Scratch::new("include");
    s.write("f", b"hi");
    let r = curl(&s, &["-s", "-i", &s.url("f")]);
    let out = String::from_utf8(r.stdout).unwrap();
    assert!(
        out.starts_with("Content-Length: 2\r\nAccept-ranges: bytes\r\nLast-Modified: "),
        "{out:?}"
    );
    assert!(out.ends_with(" GMT\r\n\r\nhi"), "{out:?}");
}

/// `--continue-at` appends past a point, or past what the output file
/// holds already.
#[test]
fn resumes_into_the_output_file() {
    let s = Scratch::new("resume");
    s.write("f", b"0123456789");
    s.write("out", b"abc");
    let r = curl(&s, &["-s", "-C", "4", "-o", "out", &s.url("f")]);
    assert_eq!(r.code, 0);
    assert_eq!(s.read("out"), b"abc456789");
    // What is there is kept, whatever it holds.
    s.write("out", b"abc");
    let r = curl(&s, &["-s", "-C", "-", "-o", "out", &s.url("f")]);
    assert_eq!(r.code, 0);
    assert_eq!(s.read("out"), b"abc3456789");
}

/// `--skip-existing` leaves an output file there alone, and says so when
/// tracing; `--write-out` is still written.
#[test]
fn skips_an_existing_output_file() {
    let s = Scratch::new("skip");
    s.write("f", b"new");
    s.write("out", b"old");
    let r = curl(
        &s,
        &[
            "--trace-ascii",
            "t",
            "--skip-existing",
            "-o",
            "out",
            "-w",
            "[%{exitcode}]",
            &s.url("f"),
        ],
    );
    assert_eq!(r.code, 0);
    assert_eq!(s.read("out"), b"old");
    assert_eq!(r.stderr, "Note: skips transfer, \"out\" exists locally\n");
    assert_eq!(r.stdout, b"[0]");
    // Without tracing, nothing is said.
    let r = curl(&s, &["--skip-existing", "-o", "out", &s.url("f")]);
    assert_eq!((r.code, &r.stderr[..]), (0, ""));
}

/// `--remote-time` gives the output file the source's modification time.
#[test]
fn keeps_the_remote_time() {
    let s = Scratch::new("time");
    s.write("f", b"x");
    let then = SystemTime::UNIX_EPOCH + Duration::from_secs(946_728_000);
    std::fs::File::options()
        .write(true)
        .open(s.0.join("f"))
        .unwrap()
        .set_modified(then)
        .unwrap();
    let r = curl(&s, &["-s", "--remote-time", "-o", "out", &s.url("f")]);
    assert_eq!(r.code, 0);
    let meta = std::fs::metadata(s.0.join("out")).unwrap();
    assert_eq!((meta.mtime(), meta.atime()), (946_728_000, 946_728_000));
    let r = curl(&s, &["-s", "-o", "plain", &s.url("f")]);
    assert_eq!(r.code, 0);
    assert_ne!(
        std::fs::metadata(s.0.join("plain")).unwrap().mtime(),
        946_728_000
    );
}

/// `--upload-file` writes the file to the URL's path; `-C -` appends what
/// the target lacks.
#[test]
fn uploads_a_file() {
    let s = Scratch::new("upload");
    s.write("src", b"0123456789");
    let r = curl(&s, &["-s", "-T", "src", &s.url("dst")]);
    assert_eq!((r.code, &r.stdout[..]), (0, &b""[..]));
    assert_eq!(s.read("dst"), b"0123456789");
    s.write("dst", b"0123");
    let r = curl(
        &s,
        &[
            "-s",
            "-C",
            "-",
            "-T",
            "src",
            &s.url("dst"),
            "-w",
            "%{size_upload}",
        ],
    );
    assert_eq!((r.code, &r.stdout[..]), (0, &b"6"[..]));
    assert_eq!(s.read("dst"), b"0123456789");
    // `-T ""` uploads nothing: a download.
    let r = curl(&s, &["-s", "-T", "", &s.url("src")]);
    assert_eq!(r.stdout, b"0123456789");
}

/// An upload that cannot be opened stops everything, with C's hint and
/// its result line.
#[test]
fn reports_an_upload_it_cannot_open() {
    let s = Scratch::new("unopened");
    let r = curl(&s, &["-T", "nosuch", &s.url("dst"), "-w", "<%{exitcode}>"]);
    assert_eq!(r.code, 26);
    // The hint names the manual where the build has one.
    let (hint, result) = r.stderr.split_once('\n').unwrap();
    assert_eq!(hint, "curl: cannot open 'nosuch'");
    assert!(result.starts_with("curl: try 'curl --help' "), "{result:?}");
    assert!(result.contains("\ncurl: (26) "), "{result:?}");
    assert_eq!(r.stdout, b"<26>");
    assert!(!s.exists("dst"));
}

/// Options for a URL that is not there, and an operation without a URL
/// after the transfers before it ran.
#[test]
fn checks_urls_as_it_reaches_them() {
    let s = Scratch::new("urls");
    s.write("f", b"x");
    let r = curl(&s, &["-s", &s.url("f"), "-o", "a", "-o", "b"]);
    assert_eq!(r.code, 0);
    let r = curl(&s, &[&s.url("f"), "-o", "a", "-o", "b"]);
    assert!(
        r.stderr
            .contains("Warning: Got more output options than URLs\n"),
        "{:?}",
        r.stderr
    );
    let r = curl(&s, &["-s", "-o", "first", &s.url("f"), "--next", "-s"]);
    assert_eq!(r.code, 2);
    assert_eq!(s.read("first"), b"x");
    assert!(
        r.stderr.starts_with("curl: (2) no URL specified\n"),
        "{:?}",
        r.stderr
    );
}

/// `--trace-ascii` dumps the data to the trace file.
#[test]
fn traces_to_a_file() {
    let s = Scratch::new("trace");
    s.write("f", b"line\r\n");
    let r = curl(&s, &["-s", "--trace-ascii", "t", "-o", "out", &s.url("f")]);
    assert_eq!(r.code, 0);
    let trace = String::from_utf8(s.read("t")).unwrap();
    // Among libcurl's own lines.
    assert!(
        trace.contains("<= Recv data, 6 bytes (0x6)\n0000: line\n"),
        "{trace:?}"
    );
}

/// `--proto-default file` makes a path a URL (test 1146).
#[test]
fn takes_a_path_with_the_default_protocol() {
    let s = Scratch::new("default");
    s.write("f", b"x");
    let r = curl(&s, &["-s", "--proto-default", "file", &s.path("f")]);
    assert_eq!((r.code, &r.stdout[..]), (0, &b"x"[..]));
    let r = curl(&s, &["-s", &s.path("f")]);
    assert_eq!(r.code, 3);
}

/// Binary output to a terminal is refused, unless asked for with
/// `--output -`; the debug build takes `CURL_ISATTY` for a terminal.
#[cfg(feature = "debug-hooks")]
#[test]
fn refuses_binary_output_to_a_terminal() {
    let s = Scratch::new("binary");
    s.write("bin", b"a\0b");
    let tty = [("CURL_ISATTY", "1")];
    let r = curl_env(&s, &[&s.url("bin")], &tty);
    assert_eq!(r.code, 23);
    assert!(
        r.stderr
            .starts_with("Warning: Binary output can mess up your terminal."),
        "{:?}",
        r.stderr
    );
    assert_eq!(r.stdout, b"");
    let r = curl_env(&s, &["-o", "-", &s.url("bin")], &tty);
    assert_eq!((r.code, &r.stdout[..]), (0, &b"a\0b"[..]));
}
