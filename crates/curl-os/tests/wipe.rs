//! Wiping an argument changes what process listings show.
//!
//! The binary runs itself again with two secret arguments; the child
//! reads its own `/proc/self/cmdline` (what `ps` reads) before and after
//! wiping them, one whole and one from inside the word, as `--user=...`
//! is wiped.
//!
//! On Windows, where C wipes nothing, the child reads its command line as
//! the C library parsed it, quoting and the ANSI code page included.

#![allow(clippy::disallowed_methods, clippy::disallowed_macros)]

use std::process::Command;

#[cfg(unix)]
fn cmdline() -> String {
    std::fs::read_to_string("/proc/self/cmdline")
        .unwrap()
        .replace('\0', " ")
}

#[cfg(unix)]
fn main() {
    if std::env::var_os("CURL_OS_WIPE_CHILD").is_some() {
        let copy = curl_os::args::command_line();
        println!(
            "copy: {}",
            copy[1..]
                .iter()
                .map(|a| a.to_str().unwrap())
                .collect::<Vec<_>>()
                .join(" ")
        );
        println!("before: {}", cmdline());
        assert!(curl_os::args::wipe(1, 0));
        assert!(curl_os::args::wipe(2, "--user=".len()));
        assert!(!curl_os::args::wipe(3, 0), "no such argument");
        assert!(!curl_os::args::wipe(1, 99), "past the end");
        println!("after: {}", cmdline());
        return;
    }
    let out = Command::new(std::env::current_exe().unwrap())
        .args(["pw-one", "--user=pw-two"])
        .env("CURL_OS_WIPE_CHILD", "1")
        .output()
        .unwrap();
    let stdout = String::from_utf8(out.stdout).unwrap();
    assert!(
        out.status.success(),
        "{stdout}\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let line = |tag: &str| {
        stdout
            .lines()
            .find_map(|l| l.strip_prefix(tag))
            .unwrap_or_else(|| panic!("no {tag} in {stdout}"))
            .to_owned()
    };
    // The capture ran, and the secrets were visible before the wipe.
    assert_eq!(line("copy: "), "pw-one --user=pw-two");
    assert!(
        line("before: ").ends_with(" pw-one --user=pw-two "),
        "{stdout}"
    );
    assert!(
        line("after: ").ends_with(" ****** --user=****** "),
        "{stdout}"
    );
    println!("wipe: ok");
}

#[cfg(windows)]
fn main() {
    if std::env::var_os("CURL_OS_WIPE_CHILD").is_some() {
        for arg in &curl_os::args::command_line()[1..] {
            println!("arg: [{}]", arg.to_str().unwrap());
        }
        return;
    }
    // Quoted by std as the C library unquotes; the last in the ANSI code
    // page (1252 here) as in UTF-16.
    let given = ["pw-one", "--user=pw two", "", r#"a\"b"#, "caf\u{e9}"];
    let out = Command::new(std::env::current_exe().unwrap())
        .args(given)
        .env("CURL_OS_WIPE_CHILD", "1")
        .output()
        .unwrap();
    let stdout = String::from_utf8(out.stdout).unwrap();
    assert!(
        out.status.success(),
        "{stdout}\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let got: Vec<&str> = stdout
        .lines()
        .filter_map(|l| l.strip_prefix("arg: [")?.strip_suffix(']'))
        .collect();
    assert_eq!(got, given, "{stdout}");
    println!("command line: ok");
}
