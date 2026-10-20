//! The curl command-line tool.

#![forbid(unsafe_code)]

use std::ffi::OsStr;
use std::process::ExitCode;

use curl_core::version::version;

/// Exit status for anything not implemented yet. No test expects it, so a
/// missing feature cannot pass a test by accident.
const NOT_IMPLEMENTED: u8 = 125;

fn main() -> ExitCode {
    let mut args = std::env::args_os().skip(1).peekable();
    // `-q`/`--disable` only stops the config file being read, and none is.
    if args
        .peek()
        .is_some_and(|a| a == OsStr::new("-q") || a == OsStr::new("--disable"))
    {
        args.next();
    }
    let (first, rest) = (args.next(), args.next());
    match (first.as_deref().and_then(OsStr::to_str), rest) {
        (Some("-V" | "--version"), None) => {
            version_info();
            ExitCode::SUCCESS
        }
        (Some("-M" | "--manual"), None) => {
            eprintln!("Warning: built-in manual was disabled at build-time");
            ExitCode::SUCCESS
        }
        _ => {
            eprintln!("curl: not implemented yet");
            ExitCode::from(NOT_IMPLEMENTED)
        }
    }
}

/// `curl --version`.
fn version_info() {
    let v = version();
    if v.features
        .iter()
        .any(|f| f.name().eq_ignore_ascii_case("debug"))
    {
        eprintln!("WARNING: this libcurl is Debug-enabled, do not use in production\n");
    }
    println!("curl {} ({}) {}", v.version, v.host, v.components());
    println!("Release-Date: {}", v.timestamp);
    if !v.protocols.is_empty() {
        // IPFS and IPNS are served over HTTP: they are listed when it is,
        // in alphabetical order among the rest.
        let http = v.protocols.iter().position(|p| p.name() == "http");
        let insert_after = http.map(|h| {
            h + v.protocols[h + 1..]
                .iter()
                .take_while(|p| p.name() < "ipfs")
                .count()
        });
        print!("Protocols:");
        for (i, p) in v.protocols.iter().enumerate() {
            print!(" {}", p.name());
            if Some(i) == insert_after {
                print!(" ipfs ipns");
            }
        }
        println!();
    }
    if !v.features.is_empty() {
        print!("Features:");
        for f in v.features {
            print!(" {}", f.name());
        }
        println!();
    }
}
