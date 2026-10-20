//! Wiping an argument changes what process listings show.
//!
//! The binary runs itself again with two secret arguments; the child
//! reads its own `/proc/self/cmdline` (what `ps` reads) before and after
//! wiping them, one whole and one from inside the word, as `--user=...`
//! is wiped.

#![allow(clippy::disallowed_methods, clippy::disallowed_macros)]

use std::process::Command;

fn cmdline() -> String {
    std::fs::read_to_string("/proc/self/cmdline")
        .unwrap()
        .replace('\0', " ")
}

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
