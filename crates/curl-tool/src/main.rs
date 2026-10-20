//! The curl command-line tool.

#![forbid(unsafe_code)]
// Tests may allocate infallibly; the non-test build is still checked.
#![cfg_attr(test, allow(clippy::disallowed_methods, clippy::disallowed_macros))]

use std::process::ExitCode;

use curl_core::error::ErrorKind;
use curl_core::version::version;

mod msgs;
mod options;

use msgs::Messages;
use options::{Parsed, Request, exit_code};

/// Exit status for anything not implemented yet. No test expects it, so a
/// missing feature cannot pass a test by accident.
const NOT_IMPLEMENTED: u8 = 125;

/// The debug test build tracks the tool's allocations (`DESIGN.md`, "Debug
/// hooks").
#[cfg(feature = "debug-hooks")]
#[global_allocator]
static ALLOCATOR: curl_alloc::track::Tracker = curl_alloc::track::Tracker;

/// Turn allocation tracking on as `src/tool_main.c` does: `CURL_MEMDEBUG`
/// names the memdump, `CURL_MEMLIMIT` the number of allocations allowed.
#[cfg(feature = "debug-hooks")]
fn memory_tracking_init() {
    use curl_alloc::track;
    // Standard output's buffer is made on first use and never freed.
    track::untracked(|| {
        let _ = std::io::stdout();
    });
    if let Some(path) = std::env::var_os("CURL_MEMDEBUG") {
        // A memdump that cannot be created leaves the test to fail on its
        // absence, as in C.
        let _ = track::start_log(std::path::Path::new(&path));
    }
    if let Some(limit) = std::env::var_os("CURL_MEMLIMIT")
        .as_deref()
        .and_then(memlimit)
    {
        track::set_limit(limit);
    }
}

/// The leading decimal number of `value`, as `curlx_str_number` reads it
/// with a maximum of `LONG_MAX`.
#[cfg(any(feature = "debug-hooks", test))]
fn memlimit(value: &std::ffi::OsStr) -> Option<u64> {
    let bytes = value.as_encoded_bytes();
    let digits = bytes.iter().take_while(|b| b.is_ascii_digit()).count();
    let n = std::str::from_utf8(&bytes[..digits])
        .ok()?
        .parse::<u64>()
        .ok()?;
    (n <= i64::MAX.unsigned_abs()).then_some(n)
}

fn main() -> ExitCode {
    let argv = command_line();
    #[cfg(feature = "debug-hooks")]
    memory_tracking_init();
    let mut msgs = Messages::new();
    if argv.len() < 2 {
        // With no arguments, only a configuration file could name a URL.
        msgs.help(&[]);
        return ExitCode::from(exit_code(ErrorKind::FailedInit));
    }
    let line = match options::parse(&argv, &mut msgs) {
        Ok(Parsed::Run(line)) => line,
        Ok(Parsed::Request(request)) => return show(request, &msgs),
        Err(e) => return ExitCode::from(exit_code(e.kind())),
    };
    if let Some((spec, prefix)) = line.unimplemented {
        let name = [prefix.as_bytes(), spec.long.as_bytes()];
        msgs.error(&[b"option ", name[0], name[1], b": not implemented yet"]);
        return ExitCode::from(NOT_IMPLEMENTED);
    }
    if line.operations.iter().any(|op| op.urls.is_empty()) {
        msgs.help(&[b"(2) no URL specified"]);
        return ExitCode::from(exit_code(ErrorKind::FailedInit));
    }
    msgs.error(&[b"transfers are not implemented yet"]);
    ExitCode::from(NOT_IMPLEMENTED)
}

/// Show what the command line asked for instead of transfers.
fn show(request: Request<'_>, msgs: &Messages) -> ExitCode {
    match request {
        Request::Version => version_info(),
        Request::Manual => msgs.warn(&[b"built-in manual was disabled at build-time"]),
        Request::Help(_) => {
            msgs.error(&[b"--help is not implemented yet"]);
            return ExitCode::from(NOT_IMPLEMENTED);
        }
        // Nothing is embedded: a build without an embedded CA bundle prints
        // nothing.
        Request::CaEmbed => {}
    }
    ExitCode::SUCCESS
}

/// The command line, as the operating system gave it.
///
/// It is read before allocation tracking starts: like C's `argv`, it is the
/// process's input rather than memory curl allocates, and the C debug
/// build's memdump never shows it. Copying it out of the OS is the one
/// infallible allocation the tool keeps.
#[allow(
    clippy::disallowed_methods,
    reason = "the command line is copied once, before anything is tracked"
)]
fn command_line() -> Vec<std::ffi::OsString> {
    std::env::args_os().collect()
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

#[cfg(test)]
mod tests {
    use super::*;

    /// As `curlx_str_number`: leading digits, at most `LONG_MAX`.
    #[test]
    fn reads_memlimit_like_c() {
        let read = |s: &str| memlimit(std::ffi::OsStr::new(s));
        assert_eq!(read("140"), Some(140));
        assert_eq!(read("0"), Some(0));
        assert_eq!(read("12abc"), Some(12));
        assert_eq!(read(""), None);
        assert_eq!(read("-3"), None);
        assert_eq!(read("9223372036854775807"), Some(9223372036854775807));
        assert_eq!(read("9223372036854775808"), None);
    }
}
