//! The curl command-line tool.

#![forbid(unsafe_code)]
// Tests may allocate infallibly; the non-test build is still checked.
#![cfg_attr(test, allow(clippy::disallowed_methods, clippy::disallowed_macros))]

use std::ffi::OsString;
use std::os::unix::ffi::OsStringExt as _;
use std::process::ExitCode;

use curl_alloc::OutOfMemory;
use curl_core::error::ErrorKind;
use curl_core::version::version;

mod bar;
mod config;
mod easysrc;
mod form;
mod glob;
mod help;
mod hugehelp;
mod ipfs;
#[rustfmt::skip]
mod manual;
mod msgs;
mod operate;
mod options;
mod output;
mod slurp;
mod sockopt;
mod stdio;
mod stdout;
mod trace;
#[cfg(test)]
mod untrusted;
mod vars;
mod write_out;
mod xattr;

use msgs::Messages;
use options::{CommandLine, Parsed, Request, Trace, Unimplemented, exit_code};

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
    // Read before tracking starts, so std's infallible copies are not
    // counted, as C reads them before its memory debugging starts.
    #[allow(clippy::disallowed_methods)]
    let (memdebug, memlimit_value) = (
        std::env::var_os("CURL_MEMDEBUG"),
        std::env::var_os("CURL_MEMLIMIT"),
    );
    if let Some(path) = memdebug {
        // A memdump that cannot be created leaves the test to fail on its
        // absence, as in C.
        let _ = track::start_log(std::path::Path::new(&path));
    }
    if let Some(limit) = memlimit_value.as_deref().and_then(memlimit) {
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
    // C's `curl_global_init`: OpenSSL's configuration is read now, and
    // the key log opened.
    curl_openssl::init();
    operate::KEYLOG.open();
    // C takes the environment's locale but for numbers (`operate`).
    curl_os::locale::from_environment_but_numbers();
    let mut msgs = Messages::new();
    let curlrc = if config::reads_curlrc(&argv) {
        match config::find_curlrc(
            |var| Ok(curl_os::env::var(var.as_bytes())?.map(OsString::from_vec)),
            curl_os::users::home_directory,
            config::readable,
        ) {
            Ok(found) => found,
            Err(OutOfMemory) => {
                msgs.error(&[b"out of memory"]);
                return ExitCode::from(exit_code(ErrorKind::OutOfMemory));
            }
        }
    } else {
        None
    };
    let curlrc_name = curlrc
        .as_ref()
        .map(|path| path.as_os_str().as_encoded_bytes());
    let mut wipe = |index, offset| {
        assert!(
            curl_os::args::wipe(index, offset),
            "argument {index} has {offset} bytes to keep"
        );
    };
    options::parse(
        &argv,
        curlrc_name,
        &mut msgs,
        &mut wipe,
        |parsed, msgs| match parsed {
            Ok(Parsed::Run(mut line)) => run(&mut line, argv.len(), curlrc_name, msgs),
            Ok(Parsed::Request(request)) => show(request, msgs),
            Err(e) => ExitCode::from(exit_code(e.kind())),
        },
    )
}

/// Run what `line` asks for; `argc` words were given, and `curlrc` is the
/// default configuration file, if one was read.
fn run(
    line: &mut CommandLine<'_>,
    argc: usize,
    curlrc: Option<&[u8]>,
    msgs: &mut Messages,
) -> ExitCode {
    // With no arguments, only a configuration file could name a URL.
    let first_url = line.operations[0].nodes.first().and_then(|n| n.url);
    if argc < 2 && first_url.is_none() {
        msgs.help(&[]);
        return ExitCode::from(exit_code(ErrorKind::FailedInit));
    }
    if let Some(Unimplemented::Option(spec, prefix)) = line.unimplemented {
        let name = [prefix.as_bytes(), spec.long.as_bytes()];
        msgs.error(&[b"option ", name[0], name[1], b": not implemented yet"]);
        return ExitCode::from(NOT_IMPLEMENTED);
    }
    msgs.tracing = line.global.trace != Trace::None;
    // The debug build's `CURL_DEBUG` has the last word on the library's
    // components, as C applies it after each `curl_global_trace`.
    #[cfg(feature = "debug-hooks")]
    {
        let given = curl_os::env::var(b"CURL_DEBUG");
        let applied = given.and_then(|config| {
            if let Some(config) = config {
                line.global.components()?.configure(&config);
            }
            Ok(())
        });
        if applied.is_err() {
            msgs.error(&[b"out of memory"]);
            return ExitCode::from(exit_code(ErrorKind::OutOfMemory));
        }
    }
    // Noted once the verbosity is known.
    if line.read_curlrc
        && let Some(name) = curlrc
    {
        msgs.note(&[b"Read config file from '", name, b"'"]);
    }
    match operate::run(line, *msgs) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => ExitCode::from(exit_code(e)),
    }
}

/// An operating system error's message, as `curlx_strerror` gives it:
/// without the number std adds, and made without allocating.
pub(crate) fn os_message(e: &std::io::Error) -> curl_os::error::ErrorText {
    curl_os::error::ErrorText::of(e)
}

/// Show what the command line asked for instead of transfers.
fn show(request: Request<'_>, msgs: &Messages) -> ExitCode {
    match request {
        Request::Version => version_info(),
        Request::Manual => hugehelp::show_all(),
        Request::Help(topic) => help::show(topic, msgs.columns()),
        // Nothing is embedded: a build without an embedded CA bundle prints
        // nothing.
        Request::CaEmbed => {}
        Request::Engines => list_engines(),
    }
    ExitCode::SUCCESS
}

/// `--engine list` (`tool_list_engines`): the TLS library's crypto
/// engines, `<none>` if it has none or they cannot be listed. A failure
/// to write stops the rest, as `puts` and `printf` would only fail again.
fn list_engines() {
    use curl_core::tls::TlsBackend as _;
    use std::io::Write as _;
    let ids = curl_openssl::OPENSSL.engines().unwrap_or_default();
    let mut out = std::io::stdout().lock();
    let none: &[&[u8]] = &[b"<none>"];
    let shown = ids.iter().map(Vec::as_slice);
    let written = out.write_all(b"Build-time engines:\n").and_then(|()| {
        let mut each = |id: &[u8]| {
            out.write_all(b"  ")?;
            out.write_all(id)?;
            out.write_all(b"\n")
        };
        if ids.is_empty() {
            none.iter().try_for_each(|id| each(id))
        } else {
            shown.into_iter().try_for_each(each)
        }
    });
    // C does not look at what its writes return.
    if written.is_ok() {
        let _ = out.flush();
    }
}

/// The command line, as the operating system gave it.
///
/// It is read before allocation tracking starts: like C's `argv`, it is the
/// process's input rather than memory curl allocates, and the C debug
/// build's memdump never shows it.
fn command_line() -> Vec<std::ffi::OsString> {
    curl_os::args::command_line()
}

/// What `curl_version` says of the library the tool runs: it and the
/// libraries it links, in C's order.
pub(crate) struct CurlVersion;

impl std::fmt::Display for CurlVersion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use curl_core::version::Library;
        let ssl = curl_openssl::version();
        let zlib = Library("zlib", curl_zlib::version());
        let brotli = Library("brotli", curl_brotli::version());
        let zstd = Library("zstd", curl_zstd::version());
        let psl = Library("libpsl", curl_psl::version());
        let gss = Library("mit-krb5", curl_gssapi::version());
        let libraries: [&dyn std::fmt::Display; 6] = [&ssl, &zlib, &brotli, &zstd, &psl, &gss];
        version().components(&libraries).fmt(f)
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
    println!("curl {} ({}) {CurlVersion}", v.version, v.host);
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

    /// The message is the system's text alone, made without allocating,
    /// as `curlx_strerror` writes it into a buffer on the stack: an
    /// allocation the tool could not refuse would abort the torture run
    /// (test 1683).
    #[cfg(feature = "debug-hooks")]
    #[test]
    fn gives_an_os_error_s_message_without_allocating() {
        // ENOENT, 2 on every Unix.
        let e = std::io::Error::from_raw_os_error(2);
        let (message, cost) = curl_alloc::track::measure(|| os_message(&e));
        assert_eq!(message.as_bytes(), b"No such file or directory");
        assert_eq!(cost.allocations, 0, "the message allocated");
    }

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

    /// `curl -V` lists the libraries after libcurl as C's does: in its
    /// order, each named as it names it, without those not linked.
    #[test]
    fn names_the_libraries_as_c() {
        let want = format!(
            "libcurl/{} {} zlib/{} brotli/{} zstd/{} libpsl/{} mit-krb5/{}",
            version().version,
            curl_openssl::version(),
            curl_zlib::version(),
            curl_brotli::version(),
            curl_zstd::version(),
            curl_psl::version(),
            curl_gssapi::version()
        );
        assert_eq!(CurlVersion.to_string(), want);
    }
}
