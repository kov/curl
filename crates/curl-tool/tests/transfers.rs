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

/// A URL's patterns make a transfer each, whose output name reads them;
/// `--globoff` takes the URL and the name as they are.
#[test]
fn globs_unless_told_not_to() {
    let dir = Scratch::new("glob");
    dir.write("a1", b"one");
    dir.write("a2", b"two");
    dir.write("a[1-2]", b"both");
    let url = dir.url("a[1-2]");
    let run = curl(&dir, &[&url, "-o", &dir.path("out#1")]);
    assert_eq!(run.code, 0, "{}", run.stderr);
    assert_eq!(dir.read("out1"), b"one");
    assert_eq!(dir.read("out2"), b"two");
    let run = curl(&dir, &["-g", &url, "-o", &dir.path("out#1")]);
    assert_eq!(run.code, 0, "{}", run.stderr);
    assert_eq!(dir.read("out#1"), b"both");
}

/// `--create-dirs` makes the directories an output file is in, those
/// already there gone through.
#[test]
fn creates_the_output_directories() {
    let dir = Scratch::new("dirs");
    dir.write("in", b"data");
    std::fs::create_dir(dir.0.join("d1")).unwrap();
    let run = curl(
        &dir,
        &[
            "--create-dirs",
            &dir.url("in"),
            "-o",
            &dir.path("d1/d2/d3/out"),
        ],
    );
    assert_eq!(run.code, 0, "{}", run.stderr);
    assert_eq!(dir.read("d1/d2/d3/out"), b"data");
    let mode = std::fs::metadata(dir.0.join("d1/d2")).unwrap().mode();
    assert_eq!(mode & 0o777, 0o750 & !umask(&dir));
    let run = curl(&dir, &[&dir.url("in"), "-o", &dir.path("e/out")]);
    assert_eq!(run.code, 23, "without, the file cannot be made");
}

/// The process's file mode mask, as a shell in `dir` reports it.
fn umask(dir: &Scratch) -> u32 {
    let out = Command::new("sh")
        .args(["-c", "umask"])
        .current_dir(&dir.0)
        .output()
        .unwrap();
    u32::from_str_radix(String::from_utf8(out.stdout).unwrap().trim(), 8).unwrap()
}

/// `--retry` tries a failure again as many times as asked, saying how long
/// it waits and how many tries are left; `--retry-all-errors` makes any
/// failure one to try again.
#[test]
fn retries_a_failure() {
    let dir = Scratch::new("retry");
    let missing = dir.url("missing");
    let w = "%{num_retries}\n";
    let run = curl(
        &dir,
        &["--retry", "2", "--retry-delay", "0.01", "-w", w, &missing],
    );
    assert_eq!(run.code, 37, "not one to try again: {}", run.stderr);
    assert_eq!(run.stdout, b"0\n");
    let all = [
        "--retry",
        "2",
        "--retry-delay",
        "0.01",
        "--retry-all-errors",
    ];
    let run = curl(&dir, &[&all[..], &["-w", w, &missing]].concat());
    assert_eq!(run.code, 37);
    assert_eq!(run.stdout, b"2\n");
    // Each attempt's failure is said; the warnings are wrapped as C wraps
    // them.
    let failed = format!("curl: (37) Could not open file {}\n", dir.path("missing"));
    let expected = [
        &failed[..],
        "Warning: Problem (retrying all errors). Retrying in 0.010 seconds. 2 retries \n",
        "Warning: left.\n",
        &failed,
        "Warning: Problem (retrying all errors). Retrying in 0.010 seconds. 1 retry \n",
        "Warning: left.\n",
        &failed,
    ]
    .concat();
    assert_eq!(run.stderr, expected);
}

/// `--url @file` reads URLs from a file, one a line, comments and blank
/// lines left out; each is saved as `-O` names it, and never globbed.
#[test]
fn reads_urls_from_a_file() {
    let dir = Scratch::new("url-file");
    std::fs::create_dir(dir.0.join("src")).unwrap();
    std::fs::create_dir(dir.0.join("out")).unwrap();
    dir.write("src/a", b"A");
    dir.write("src/b{1,2}", b"B");
    let urls = format!(
        "{}\n\n  # not one\n{}\n",
        dir.url("src/a"),
        dir.url("src/b{1,2}")
    );
    dir.write("urls", urls.as_bytes());
    let run = curl(&dir, &["--url", "@urls", "--output-dir", "out"]);
    assert_eq!(run.code, 0, "{}", run.stderr);
    assert_eq!(dir.read("out/a"), b"A");
    assert_eq!(dir.read("out/b{1,2}"), b"B");
    let run = curl(&dir, &["--url", "@missing"]);
    assert_eq!(run.code, 26);
    assert!(
        run.stderr
            .starts_with("curl: option --url: error encountered when reading a file\n"),
        "{}",
        run.stderr
    );
}

/// `-K` reads options from a file as they are met, one file naming the
/// next; an error in one is reported at each level that read it.
#[test]
fn reads_options_from_files() {
    let dir = Scratch::new("config");
    dir.write("in", b"data");
    let inner = format!("output = \"{}\"\n", dir.path("out"));
    dir.write("inner", inner.as_bytes());
    let outer = format!(
        "# a comment\nurl {}\n-K {}\n",
        dir.url("in"),
        dir.path("inner")
    );
    dir.write("outer", outer.as_bytes());
    let run = curl(&dir, &["-K", &dir.path("outer")]);
    assert_eq!(run.code, 0, "{}", run.stderr);
    assert_eq!(dir.read("out"), b"data");
    // Comments and blank lines are not counted. Short names keep the
    // messages from being wrapped.
    dir.write("bad", b"\n# no\nfail\n--bogus\n");
    dir.write("cfg", b"fail\nconfig=bad\n");
    let run = curl(&dir, &["--config", "cfg", &dir.url("in")]);
    assert_eq!(run.code, 2);
    // The hint after names the manual if the build has it.
    let lines: Vec<&str> = run.stderr.lines().take(3).collect();
    assert_eq!(
        lines,
        [
            "curl: bad:2 config file option '--bogus' is unknown",
            "curl: cfg:2 config file option 'config' found an unknown config option",
            "curl: option --config: found an unknown config option",
        ]
    );
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

/// A file a time condition rules out leaves the output file as it was,
/// not even emptied (test 1424 over HTTP).
#[test]
fn an_unmet_time_condition_leaves_the_output_alone() {
    let s = Scratch::new("timecond");
    s.write("f", b"new");
    s.write("out", b"original");
    let r = curl(&s, &["-s", "-z", "1 jan 2100", "-o", "out", &s.url("f")]);
    assert_eq!(r.code, 0);
    assert_eq!(s.read("out"), b"original");
    let r = curl(&s, &["-s", "-z", "1 jan 2000", "-o", "out", &s.url("f")]);
    assert_eq!(r.code, 0);
    assert_eq!(s.read("out"), b"new");
}

/// The result line, with the library's reason, muted by `--silent`
/// unless `--show-error`.
#[test]
fn reports_a_failure() {
    let s = Scratch::new("failure");
    let r = curl(&s, &["--no-progress-meter", &s.url("missing")]);
    assert_eq!(r.code, 37);
    let line = format!("curl: (37) Could not open file {}\n", s.path("missing"));
    assert_eq!(r.stderr, line);
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

/// `--netrc-file` names a file that must exist when the option is read.
#[test]
fn refuses_a_netrc_file_that_is_not_there() {
    let s = Scratch::new("netrc");
    let r = curl(&s, &["--netrc-file", "missing", &s.url("f")]);
    assert_eq!(r.code, 2);
    assert!(
        r.stderr.starts_with(
            "curl: The file 'missing' provided to --netrc-file does not exist\n\
             curl: option --netrc-file: is badly used here\n"
        ),
        "{}",
        r.stderr
    );
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
    // From 0 is from the start: the file is written over.
    s.write("out", b"abc");
    let r = curl(&s, &["-s", "-C", "0", "-o", "out", &s.url("f")]);
    assert_eq!(r.code, 0);
    assert_eq!(s.read("out"), b"0123456789");
}

/// An output file that cannot be created fails the transfer, with the
/// reason; one that cannot be opened to resume into fails setting it up,
/// which is still reported as the transfer's result.
#[test]
fn reports_an_output_it_cannot_open() {
    let s = Scratch::new("unwritable");
    s.write("f", b"x");
    let quiet = "--no-progress-meter";
    let r = curl(
        &s,
        &[quiet, "-o", "no/out", "-w", "<%{exitcode}>", &s.url("f")],
    );
    assert_eq!((r.code, &r.stdout[..]), (23, &b"<23>"[..]));
    assert!(
        r.stderr.starts_with(
            "Warning: Failed to open the file no/out: No such file or directory\ncurl: (23) "
        ),
        "{:?}",
        r.stderr
    );
    let args = [quiet, "-C", "4", "-o", "no/out", "-w", "<%{exitcode}>"];
    let r = curl(&s, &[&args[..], &[&s.url("f"), &s.url("f")]].concat());
    assert_eq!((r.code, &r.stdout[..]), (23, &b"<23>"[..]));
    assert!(
        r.stderr
            .starts_with("curl: cannot open 'no/out'\ncurl: (23) "),
        "{:?}",
        r.stderr
    );
}

/// Standard output is buffered, as stdio buffers it: a write that fails
/// fails when the transfer's output is flushed at its end.
#[test]
fn reports_standard_output_it_cannot_write() {
    let s = Scratch::new("full");
    s.write("f", b"x\n");
    let tool = std::env::var_os("CURL_TOOL_UNDER_TEST")
        .map_or_else(|| PathBuf::from(env!("CARGO_BIN_EXE_curl")), PathBuf::from);
    let out = Command::new(tool)
        .args(["-q", "-sS", &s.url("f")])
        .stdout(
            std::fs::File::options()
                .write(true)
                .open("/dev/full")
                .unwrap(),
        )
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(23));
    assert_eq!(out.stderr, b"curl: Failed writing body\n");
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

/// A file that opens but cannot be read fails its upload with a read
/// error; C sends nothing and succeeds. A deliberate difference from C
/// (SCOPE.md, "Where it differs from C"), so this test fails on its tool.
#[test]
fn an_upload_that_cannot_be_read_fails() {
    let s = Scratch::new("unreadable");
    std::fs::create_dir(s.0.join("dir")).unwrap();
    let r = curl(&s, &["-s", "-T", "dir", &s.url("dst"), "-w", "%{exitcode}"]);
    assert_eq!((r.code, &r.stdout[..]), (26, &b"26"[..]));
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

/// A trace option that changes the kind of trace says so; one that keeps
/// it does not.
#[test]
fn warns_of_trace_options_overridden() {
    let s = Scratch::new("overrides");
    s.write("f", b"x");
    let warned = |args: &[&str]| {
        let r = curl(
            &s,
            &[&["--no-progress-meter", "-o", "out"], args, &[&s.url("f")]].concat(),
        );
        assert_eq!(r.code, 0, "{args:?}");
        r.stderr
            .lines()
            .filter(|l| l.starts_with("Warning: "))
            .map(str::to_owned)
            .collect::<Vec<_>>()
    };
    let to_trace = "Warning: --trace overrides an earlier trace/verbose option";
    let to_ascii = "Warning: --trace-ascii overrides an earlier trace/verbose option";
    let to_verbose = "Warning: -v, --verbose overrides an earlier trace option";
    assert_eq!(warned(&["--trace", "t"]), [""; 0]);
    assert_eq!(warned(&["--trace", "t", "--trace", "t"]), [""; 0]);
    assert_eq!(warned(&["--trace-ascii", "t", "--trace", "t"]), [to_trace]);
    assert_eq!(warned(&["--trace", "t", "--trace-ascii", "t"]), [to_ascii]);
    assert_eq!(warned(&["-v", "--trace", "t"]), [to_trace]);
    assert_eq!(warned(&["--trace", "t", "-v"]), [to_verbose]);
    assert_eq!(warned(&["--trace-ascii", "t", "-v"]), [to_verbose]);
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

/// A refused pattern is shown with a caret under its column; one with no
/// column is shown alone.
#[test]
fn reports_a_bad_pattern() {
    let s = Scratch::new("badglob");
    let r = curl(&s, &["h/[2-1]"]);
    assert_eq!(r.code, 3);
    assert_eq!(
        r.stderr,
        "curl: (3) bad range in position 8:\nh/[2-1]\n       ^\n"
    );
    let r = curl(&s, &[&format!("h/{}", "{a,b}".repeat(64))]);
    assert_eq!((r.code, &r.stderr[..]), (3, "curl: (3) range overflow\n"));
}
