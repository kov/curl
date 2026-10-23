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

/// `--retry-max-time` stops the retries once that long has gone by since
/// the first attempt.
#[test]
fn retries_for_as_long_as_allowed() {
    let dir = Scratch::new("retry-max");
    let args = [
        "-s",
        "--retry",
        "50",
        "--retry-all-errors",
        "--retry-delay",
        "0.05",
        "--retry-max-time",
        "0.3",
        "-w",
        "%{num_retries}",
    ];
    let missing = dir.url("missing");
    let run = curl(&dir, &[&args[..], &[&missing]].concat());
    assert_eq!(run.code, 37);
    let retries: u32 = String::from_utf8(run.stdout).unwrap().parse().unwrap();
    assert!((1..20).contains(&retries), "{retries}");
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

/// Run the tool with `args`, in `dir`, its standard output going to
/// `stdout`; `None` is a pipe whose reader is gone before the tool starts.
fn curl_to(dir: &Scratch, args: &[&str], stdout: Option<&str>) -> Run {
    let tool = std::env::var_os("CURL_TOOL_UNDER_TEST")
        .map_or_else(|| PathBuf::from(env!("CARGO_BIN_EXE_curl")), PathBuf::from);
    let mut cmd = Command::new(tool);
    cmd.arg("-q")
        .args(args)
        .current_dir(&dir.0)
        .stderr(std::process::Stdio::piped());
    match stdout {
        Some(path) => {
            let file = std::fs::File::options()
                .write(true)
                .create(true)
                .truncate(true)
                .open(path)
                .unwrap();
            cmd.stdout(file);
        }
        None => {
            // Closed here, not after the spawn, where the tool may already
            // have written into the pipe.
            let (reader, writer) = std::io::pipe().unwrap();
            drop(reader);
            cmd.stdout(writer);
        }
    }
    let out = cmd.spawn().unwrap().wait_with_output().unwrap();
    Run {
        code: out.status.code().unwrap(),
        stdout: out.stdout,
        stderr: String::from_utf8(out.stderr).unwrap(),
    }
}

/// Output goes through stdio's buffer, as C's `fwrite` sends it: a write
/// that does not fit the buffer is tried at once, and fails with the count
/// it got, while one that fits fails only when the buffer is written, at
/// the end of the transfer or at once with `--no-buffer`. As the C tool
/// does on a full device and a closed pipe.
#[test]
fn reports_output_it_cannot_write_when_stdio_would() {
    let s = Scratch::new("stdio");
    // Over two of the device's 4096-byte blocks, under one piece of a
    // `file://` read; and less than a block.
    s.write("big", &[b'x'; 10000]);
    s.write("small", &[b'x'; 3000]);
    let (big, small) = (s.url("big"), s.url("small"));
    let full = Some("/dev/full");
    let short = "curl: (23) Failure writing output to destination, passed 10000 returned 0\n";
    let at_close = "curl: curl: (23) Failed writing body\n";
    let at_flush = "curl: Failed writing body\n";
    let flushed = "curl: (23) client returned ERROR on write of 3000 bytes\n";
    // stdio's buffer: the device's block size, at most `BUFSIZ`.
    let block = std::fs::metadata("/dev/full").unwrap().blksize().min(8192);
    let headed = format!(
        "curl: (23) Failure writing output to destination, passed 10000 returned {}\n",
        block - 93
    );
    let cases: [(&[&str], Option<&str>, &str); 10] = [
        (&["-o", "/dev/full", &big], None, short),
        (&[&big], full, short),
        (&["-N", "-o", "/dev/full", &big], None, short),
        (&["-o", "/dev/full", &small], None, at_close),
        (&[&small], full, at_flush),
        (&[&small], None, at_flush),
        (&["-N", "-o", "/dev/full", &small], None, flushed),
        (&["-N", &small], full, flushed),
        // Header lines shown are written unchecked, into the buffer: the
        // body fills the rest of it, less their 93 bytes, and fails as it
        // is written.
        (&["-i", "-o", "/dev/full", &small], None, at_close),
        (&["-i", &big], full, &headed),
    ];
    for (args, stdout, want) in cases {
        let r = curl_to(&s, &[&["-sS"], args].concat(), stdout);
        assert_eq!((r.code, &r.stderr[..]), (23, want), "{args:?}");
    }
    // The failure at close is the transfer's result.
    let w = s.path("w");
    let r = curl_to(
        &s,
        &["-sS", "-o", "/dev/full", "-w", "%{exitcode}", &small],
        Some(&w),
    );
    assert_eq!((r.code, &r.stderr[..]), (23, at_close));
    assert_eq!(s.read("w"), b"23");
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
/// (DIVERGENCE.md), so this test fails on its tool.
#[test]
fn an_upload_that_cannot_be_read_fails() {
    let s = Scratch::new("unreadable");
    std::fs::create_dir(s.0.join("dir")).unwrap();
    let r = curl(&s, &["-s", "-T", "dir", &s.url("dst"), "-w", "%{exitcode}"]);
    assert_eq!((r.code, &r.stdout[..]), (26, &b"26"[..]));
}

/// Header lines `-i` cannot write fail the transfer though no body write
/// follows to fail: those writes are not checked, and the output they
/// are held in fails to be written when it is closed.
#[test]
fn an_included_header_that_cannot_be_written_fails() {
    let s = Scratch::new("headerfull");
    s.write("empty", b"");
    let w = "[%{exitcode}]";
    let r = curl(
        &s,
        &["-s", "-i", "-o", "/dev/full", &s.url("empty"), "-w", w],
    );
    assert_eq!((r.code, &r.stdout[..]), (23, &b"[23]"[..]));
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

/// `--progress-bar` fills the terminal's width but for the percentage,
/// from 20 columns to 400, and ends its line after the transfer; a
/// transfer that never started draws no bar and ends no line.
#[test]
fn draws_a_progress_bar() {
    let s = Scratch::new("bar");
    s.write("f", &[b'x'; 1000]);
    let bar = |columns: &str| {
        let env = [("COLUMNS", columns)];
        let r = curl_env(&s, &["-#", &s.url("f"), "-o", &s.path("out")], &env);
        assert_eq!(r.code, 0, "{}", r.stderr);
        r.stderr
    };
    let line = |hashes: usize| format!("\r{} 100.0%\n", "#".repeat(hashes));
    assert_eq!(bar("30"), line(23));
    assert_eq!(bar("500"), line(393));
    let r = curl_env(&s, &["-#", &s.url("missing")], &[("COLUMNS", "30")]);
    assert_eq!(r.code, 37);
    let want = format!("curl: (37) Could not open file {}\n", s.path("missing"));
    assert_eq!(r.stderr, want);
}

/// A configuration file's argument that starts with a single quote, or
/// is followed by more than a comment, is warned of.
#[test]
fn warns_of_a_config_argument_likely_wrong() {
    let s = Scratch::new("cfgwarn");
    s.write("f", b"x");
    s.write("cfg", b"header: 'a b' c\n");
    let r = curl_env(&s, &["-K", "cfg", &s.url("f")], &[("COLUMNS", "500")]);
    assert_eq!(r.code, 0, "{}", r.stderr);
    assert!(
        r.stderr.starts_with(
            "Warning: cfg:1 Option 'header' uses argument with leading single quote. \
             It is probably a mistake. Consider double quotes.\n\
             Warning: cfg:1 Option 'header' uses argument with unquoted whitespace. \
             This may cause side-effects. Consider double quotes.\n"
        ),
        "{}",
        r.stderr
    );
}

/// `--location` and `--follow` override each other, saying so.
#[test]
fn warns_of_redirect_options_overridden() {
    let s = Scratch::new("follow");
    s.write("f", b"x");
    let url = s.url("f");
    let warned = |args: &[&str]| {
        let r = curl(&s, args);
        assert_eq!(r.code, 0, "{}", r.stderr);
        r.stderr.lines().next().unwrap_or_default().to_owned()
    };
    assert_eq!(
        warned(&["--no-progress-meter", "--follow", "-L", &url]),
        "Warning: --location overrides --follow"
    );
    assert_eq!(
        warned(&["--no-progress-meter", "-L", "--follow", &url]),
        "Warning: --follow overrides --location"
    );
    assert_eq!(warned(&["--no-progress-meter", "-L", "-L", &url]), "");
    assert_eq!(
        warned(&["--no-progress-meter", "--follow", "--follow", &url]),
        ""
    );
}

/// A configuration file that does not open, one giving an argument to
/// an option that takes none, and one naming itself until the levels run
/// out, each fail the command line.
#[test]
fn refuses_bad_config_files() {
    let s = Scratch::new("badcfg");
    s.write("f", b"x");
    let url = s.url("f");
    let r = curl(&s, &["-K", "nope", &url]);
    assert_eq!(r.code, 26);
    assert!(
        r.stderr.starts_with(
            "curl: cannot read config from 'nope'\n\
             curl: option -K: error encountered when reading a file\n"
        ),
        "{}",
        r.stderr
    );
    s.write("extra", b"silent x\n");
    let r = curl(&s, &["-K", "extra", &url]);
    assert_eq!(r.code, 2);
    assert!(
        r.stderr
            .starts_with("curl: option -K: had unsupported trailing garbage\n"),
        "{}",
        r.stderr
    );
    s.write("empty", b"silent \"\"\n");
    let r = curl(&s, &["-K", "empty", &url]);
    assert_eq!((r.code, &r.stdout[..]), (0, &b"x"[..]), "{}", r.stderr);
    s.write("self", b"-K self\n");
    let r = curl(&s, &["-K", "self", &url]);
    assert_eq!(r.code, 2);
    let mut want = String::from("curl: Max config file recursion level reached (5)\n");
    for _ in 0..5 {
        want.push_str("curl: self:1 config file option '-K' is badly used here\n");
    }
    want.push_str("curl: option -K: is badly used here\n");
    assert!(r.stderr.starts_with(&want), "{}", r.stderr);
}

/// The default configuration file read is noted when tracing.
#[test]
fn notes_the_default_config_file() {
    let s = Scratch::new("curlrc");
    s.write("f", b"x");
    s.write(".curlrc", b"fail\n");
    let tool = std::env::var_os("CURL_TOOL_UNDER_TEST")
        .map_or_else(|| PathBuf::from(env!("CARGO_BIN_EXE_curl")), PathBuf::from);
    let out = Command::new(tool)
        .args(["-v", &s.url("f"), "-o", &s.path("out")])
        .current_dir(&s.0)
        .env("CURL_HOME", &s.0)
        .env("COLUMNS", "500")
        .output()
        .unwrap();
    let stderr = String::from_utf8(out.stderr).unwrap();
    let want = format!("Note: Read config file from '{}'\n", s.path(".curlrc"));
    assert!(stderr.starts_with(&want), "{stderr}");
}

/// `-w @-` with nothing on standard input warns, and writes nothing.
#[test]
fn warns_of_an_empty_format_file() {
    let s = Scratch::new("emptyformat");
    s.write("f", b"x");
    let r = curl(&s, &["--no-progress-meter", "-w", "@-", &s.url("f")]);
    assert_eq!((r.code, &r.stdout[..]), (0, &b"x"[..]));
    assert_eq!(r.stderr, "Warning: Failed to read <stdin>\n");
}

/// Without arguments the tool only says how to get help; with some but
/// no URL, it says there is none first.
#[test]
fn says_how_to_get_help_without_a_url() {
    let s = Scratch::new("nourl");
    let tool = std::env::var_os("CURL_TOOL_UNDER_TEST")
        .map_or_else(|| PathBuf::from(env!("CARGO_BIN_EXE_curl")), PathBuf::from);
    // No configuration file is found to give one.
    let home = s.path("");
    // The hint names the manual where the build has one.
    for (args, said) in [(&[][..], ""), (&["-q"], "curl: (2) no URL specified\n")] {
        let out = Command::new(&tool)
            .args(args)
            .current_dir(&s.0)
            .env("HOME", &home)
            .env("CURL_HOME", &home)
            .env("XDG_CONFIG_HOME", &home)
            .output()
            .unwrap();
        let stderr = String::from_utf8(out.stderr).unwrap();
        assert_eq!(out.status.code(), Some(2), "{args:?}");
        let hint = stderr
            .strip_prefix(said)
            .unwrap_or_else(|| panic!("{args:?}: {stderr}"));
        assert!(
            hint.starts_with("curl: try 'curl --help' ")
                && hint.ends_with(" for more information\n")
                && hint.matches('\n').count() == 1,
            "{args:?}: {stderr}"
        );
    }
}

/// `%{urlnum}` counts the URLs of the command line from 0.
#[test]
fn numbers_the_urls() {
    let s = Scratch::new("urlnum");
    s.write("f", b"x");
    let url = s.url("f");
    let w = "%{urlnum}\n";
    let r = curl(
        &s,
        &[
            "-s",
            "-o",
            "/dev/null",
            "-w",
            w,
            &url,
            "-o",
            "/dev/null",
            &url,
            "-o",
            "/dev/null",
            &url,
        ],
    );
    assert_eq!((r.code, &r.stdout[..]), (0, &b"0\n1\n2\n"[..]));
}

/// With `--globoff` an output name is not read for patterns, so a name
/// with `#<name>` in it is taken as it is.
#[test]
fn takes_an_output_name_as_it_is_without_globbing() {
    let s = Scratch::new("globoff-name");
    s.write("f", b"x");
    let r = curl(&s, &["-s", "-g", &s.url("f"), "-o", "out#<a>"]);
    assert_eq!(r.code, 0, "{}", r.stderr);
    assert_eq!(s.read("out#<a>"), b"x");
    let r = curl(&s, &["-s", &s.url("f"), "-o", "out2#<a>"]);
    assert_eq!(r.code, 43);
}

/// `--create-dirs` makes the directories of the `-D` file too.
#[test]
fn creates_the_header_file_directories() {
    let s = Scratch::new("dump-dirs");
    s.write("f", b"x");
    let r = curl(
        &s,
        &[
            "-s",
            "--create-dirs",
            "-D",
            "d/sub/h",
            "-o",
            "/dev/null",
            &s.url("f"),
        ],
    );
    assert_eq!(r.code, 0, "{}", r.stderr);
    assert!(s.exists("d/sub/h"));
}

/// An upload to a URL whose path ends in `/` is saved under the file's
/// name.
#[test]
fn uploads_to_a_directory_under_the_file_s_name() {
    let s = Scratch::new("upload-dir");
    s.write("src", b"data");
    std::fs::create_dir(s.0.join("up")).unwrap();
    let r = curl(&s, &["-s", "-T", "src", &s.url("up/")]);
    assert_eq!(r.code, 0, "{}", r.stderr);
    assert_eq!(s.read("up/src"), b"data");
}

/// `-O` takes what the path has after its last slash, and after a
/// backslash after that, trailing ones left out; a path without a name
/// is `curl_response`. A URL without a scheme has one guessed.
#[test]
fn names_a_remote_file_after_the_url() {
    let s = Scratch::new("remote-names");
    for (url, name) in [
        ("http://127.0.0.1:1/a/b//", "b"),
        ("http://127.0.0.1:1/a\\b\\c", "c"),
        ("http://127.0.0.1:1/a/b\\c", "c"),
        ("http://127.0.0.1:1/x\\/z", "z"),
        ("http://127.0.0.1:1/a\\", "a"),
        ("http://127.0.0.1:1/", "curl_response"),
        ("127.0.0.1:1/name", "name"),
    ] {
        let r = curl(
            &s,
            &["-s", "-O", url, "-w", "%{filename_effective}|%{exitcode}"],
        );
        assert_eq!(
            (r.code, String::from_utf8(r.stdout).unwrap()),
            (7, format!("{name}|7")),
            "{url}"
        );
    }
}

/// Data is resumed only from a position past the start.
#[test]
fn data_from_the_start_is_no_resume() {
    let s = Scratch::new("data-resume");
    let r = curl(&s, &["-s", "-d", "x", "-C", "0", "http://127.0.0.1:1/"]);
    assert_eq!(r.code, 7);
    let r = curl(&s, &["-s", "-d", "x", "-C", "5", "http://127.0.0.1:1/"]);
    assert_eq!(r.code, 43);
}

/// `--no-clobber` saves to the first numbered name not taken, trying
/// as many as the debug build's `CURL_MAX_CLOBBER` allows.
#[cfg(feature = "debug-hooks")]
#[test]
fn numbers_a_file_not_to_clobber() {
    let s = Scratch::new("clobber");
    s.write("f", b"new");
    for taken in ["out.txt", "out-1.txt", "out-2.txt"] {
        s.write(taken, b"old");
    }
    let run = |max: &str| {
        curl_env(
            &s,
            &[
                "-s",
                "--no-clobber",
                "-o",
                "out.txt",
                &s.url("f"),
                "-w",
                "%{filename_effective}",
            ],
            &[("CURL_MAX_CLOBBER", max)],
        )
    };
    // The output is then named as the last name tried.
    let r = run("3");
    assert_eq!((r.code, &r.stdout[..]), (23, &b"out-2.txt"[..]));
    assert!(!s.exists("out-3.txt"));
    let r = run("4");
    assert_eq!((r.code, &r.stdout[..]), (0, &b"out-3.txt"[..]));
    assert_eq!(s.read("out-3.txt"), b"new");
    assert_eq!(s.read("out.txt"), b"old");
    // One past C's limit is not taken: the default holds.
    let r = run("100001");
    assert_eq!((r.code, &r.stdout[..]), (0, &b"out-4.txt"[..]));
}

/// `--stderr` sends what goes to standard error to a file, or to
/// standard output for `-`.
#[test]
fn sends_standard_error_where_told() {
    let s = Scratch::new("stderr");
    let failed = "curl: (37) Could not open file ";
    let r = curl(&s, &["-sS", "--stderr", "err", &s.url("missing")]);
    assert_eq!((r.code, &r.stderr[..]), (37, ""));
    assert!(
        String::from_utf8(s.read("err"))
            .unwrap()
            .starts_with(failed)
    );
    let r = curl(&s, &["-sS", "--stderr", "-", &s.url("missing")]);
    assert_eq!((r.code, &r.stderr[..]), (37, ""));
    assert!(String::from_utf8(r.stdout).unwrap().starts_with(failed));
    assert!(!s.exists("-"));
}

/// The bar of an upload resumed where the file it adds to ends, of a
/// size not known, is full from the start: the whole is what the peer
/// says it is.
#[test]
fn draws_the_bar_of_an_upload_resumed_at_its_end() {
    let s = Scratch::new("bar-resumed");
    s.write("dst", b"0123");
    let tool = std::env::var_os("CURL_TOOL_UNDER_TEST")
        .map_or_else(|| PathBuf::from(env!("CARGO_BIN_EXE_curl")), PathBuf::from);
    let mut child = Command::new(tool)
        .args(["-q", "-#", "-T", "-", "-C", "-", &s.url("dst")])
        .env("COLUMNS", "30")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    std::io::Write::write_all(&mut child.stdin.take().unwrap(), b"0123456789").unwrap();
    let out = child.wait_with_output().unwrap();
    let stderr = String::from_utf8(out.stderr).unwrap();
    assert_eq!(out.status.code(), Some(0), "{stderr}");
    assert_eq!(stderr, format!("\r{} 100.0%\n", "#".repeat(23)));
    assert_eq!(s.read("dst"), b"0123456789");
}

/// `--version` names the tool, its release date and what it was built
/// with.
#[test]
fn says_its_version() {
    let dir = Scratch::new("version");
    let run = curl(&dir, &["--version"]);
    assert_eq!(run.code, 0, "{}", run.stderr);
    let out = String::from_utf8(run.stdout).unwrap();
    let lines: Vec<&str> = out.lines().collect();
    assert!(lines[0].starts_with("curl "), "{out}");
    assert!(lines[1].starts_with("Release-Date: "), "{out}");
    assert!(lines.iter().any(|l| l.starts_with("Protocols: ")), "{out}");
    assert!(lines.iter().any(|l| l.starts_with("Features: ")), "{out}");
}
