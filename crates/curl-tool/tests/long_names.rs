//! Files named by long names, under the debug build's torture mode: the
//! tool is run with each of its allocations refused in turn, as
//! `runtests.pl -t` runs it, and must end with an exit code every time,
//! never abort. std's calls that take a file's name copy one of 384 bytes
//! or more with an allocation that cannot fail; C passes its C string to
//! the system and allocates nothing for it.

#![allow(clippy::disallowed_methods, clippy::disallowed_macros)]

use std::os::unix::process::ExitStatusExt as _;
use std::path::{Path, PathBuf};
use std::process::Command;

/// A directory of its own for a test, removed after it.
struct Scratch(PathBuf);

impl Scratch {
    fn new(name: &str) -> Scratch {
        let dir = std::env::temp_dir().join(format!("curl-tool-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir(&dir).unwrap();
        Scratch(dir)
    }

    /// `name` in the directory, by a name longer than std's 384-byte
    /// buffer on the stack: `./` repeated before it.
    fn long(&self, name: &str) -> String {
        let mut long = format!("{}/", self.0.to_str().unwrap());
        while long.len() < 400 {
            long.push_str("./");
        }
        long + name
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.0).unwrap();
    }
}

/// Run the tool with `args` and `env` with no allocation refused, then
/// with each refused in turn, the first, the second and on, until a run
/// has none refused. `reset` puts the files back before each run. Every
/// run must end with an exit code, not a signal.
fn tortured(dir: &Path, args: &[&str], env: &[(&str, &str)], reset: impl Fn()) {
    let memdump = dir.join("memdump");
    let run = |limit: Option<u64>| {
        reset();
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_curl"));
        cmd.args(args).current_dir(dir).envs(env.iter().copied());
        cmd.env("CURL_MEMDEBUG", &memdump);
        if let Some(limit) = limit {
            cmd.env("CURL_MEMLIMIT", limit.to_string());
        }
        let out = cmd.output().unwrap();
        let log = std::fs::read_to_string(&memdump).unwrap_or_default();
        std::fs::remove_file(&memdump).ok();
        (out, log)
    };
    let (out, log) = run(None);
    assert!(out.status.success(), "{args:?}: {out:?}");
    assert!(
        log.contains("malloc("),
        "{args:?}: no allocation tracked:\n{log}"
    );
    for limit in 0.. {
        let (out, log) = run(Some(limit));
        assert!(
            out.status.signal().is_none(),
            "{args:?} with allocation {} refused: {out:?}\n{}",
            limit + 1,
            log.lines().rev().take(8).collect::<Vec<_>>().join("\n")
        );
        if !log.contains("reached memlimit") {
            assert!(limit > 0, "{args:?}: the first allocation was not refused");
            break;
        }
    }
}

/// Download to an output file made in a directory made for it, resumed
/// and given the remote time; the time condition, netrc, the
/// configuration file and the `--write-out` output file each named long,
/// and standard error pointed at a file named long.
#[test]
fn downloads_with_long_names_under_torture() {
    let s = Scratch::new("long-download");
    std::fs::write(s.0.join("src"), b"hello\n").unwrap();
    std::fs::write(s.0.join("netrc"), b"").unwrap();
    std::fs::write(s.0.join("config"), b"silent\n").unwrap();
    let url = format!("file://{}", s.0.join("src").to_str().unwrap());
    let (src, netrc, config) = (s.long("src"), s.long("netrc"), s.long("config"));
    let (out, err) = (s.long("made/out"), s.long("err"));
    let output = format!("%output{{{}}}done", s.long("wo"));
    // Not modified since: the condition is met.
    let since = format!("-{src}");
    let args = [
        "-q",
        "--create-dirs",
        "-o",
        &out,
        "-C",
        "-",
        "-R",
        "-z",
        &since,
        "--netrc-file",
        &netrc,
        "-K",
        &config,
        "--stderr",
        &err,
        "-w",
        &output,
        &url,
    ];
    tortured(&s.0, &args, &[], || {
        std::fs::remove_dir_all(s.0.join("made")).ok();
    });
}

/// The default configuration file, found in a directory named long,
/// and data read from a file named long.
#[test]
fn finds_the_configuration_by_a_long_name_under_torture() {
    let s = Scratch::new("long-curlrc");
    std::fs::write(s.0.join(".curlrc"), b"silent\n").unwrap();
    std::fs::write(s.0.join("src"), b"hello\n").unwrap();
    let url = format!("file://{}", s.0.join("src").to_str().unwrap());
    let home = s.long("");
    let data = format!("@{}", s.long("src"));
    let env = [("CURL_HOME", home.as_str())];
    let args = ["-o", "out", "--data-binary", &data, &url];
    tortured(&s.0, &args, &env, || {});
}

/// An upload from a file named long.
#[test]
fn uploads_from_a_long_name_under_torture() {
    let s = Scratch::new("long-upload");
    std::fs::write(s.0.join("src"), b"hello\n").unwrap();
    let url = format!("file://{}", s.0.join("dst").to_str().unwrap());
    let src = s.long("src");
    tortured(&s.0, &["-q", "-T", &src, &url], &[], || {});
}
