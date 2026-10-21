//! Running what the command line asks for: each URL's transfer, one after
//! another (`src/tool_operate.c`, its serial path).

use std::ffi::OsStr;
use std::fs::{File, FileTimes};
use std::io::{IsTerminal as _, Read as _, Seek as _, SeekFrom};
use std::num::{NonZeroU64, NonZeroUsize};
use std::os::unix::ffi::OsStrExt as _;
use std::time::{Duration, UNIX_EPOCH};

use curl_alloc::{OutOfMemory, TryVec as _, try_format};
use curl_core::easy::Easy;
use curl_core::error::{ErrorKind, UrlErrorKind};
use curl_core::handler::{Handler, Read, ReadHandler, Rewind, RewindFailed};
use curl_core::multi::TransferCx;
use curl_core::options::{self, Method, Progress, UploadSource};
use curl_core::time::TimeLimit;
use curl_core::url::{GetOptions, ParseOptions, Part, Url};

use crate::msgs::Messages;
use crate::options::{
    self as tool, CommandLine, Global, HttpVersion, Node, Operation, Output, Resume, Upload,
    exit_code,
};
use crate::os_message;
use crate::output;
use crate::stdout::Stdout;
use crate::trace::Tracer;
use crate::write_out::{self, Facts};

/// How running the command line ended.
pub(crate) enum Ending {
    /// With this result, the last transfer's unless a run was cut short.
    Done(Result<(), ErrorKind>),
    /// At something not implemented yet.
    NotImplemented(&'static str),
}

/// What became of one URL.
enum Step {
    /// Its transfer ran, or was skipped, with this result.
    Ran(Result<(), ErrorKind>),
    /// It could not be set up: nothing more runs (C's failed
    /// `create_transfer`).
    Failed(ErrorKind),
    /// Its upload could not be opened: nothing more runs, and the result
    /// is the last failure's (C's failed `pre_transfer`).
    Unopened(ErrorKind),
    NotImplemented(&'static str),
}

/// Run every operation's transfers in turn (`serial_transfers`).
pub(crate) fn run(line: &CommandLine<'_>, msgs: Messages) -> Ending {
    let Ok(stdout) = Stdout::new() else {
        return Ending::Done(Err(ErrorKind::OutOfMemory));
    };
    let tracer = match Tracer::new(&line.global, &stdout) {
        Ok(tracer) => tracer,
        Err(OutOfMemory) => return Ending::Done(Err(ErrorKind::OutOfMemory)),
    };
    let run = Shared {
        global: &line.global,
        stdout: &stdout,
        tracer: tracer.as_ref(),
        msgs,
    };
    let ending = run_all(line, &run);
    // What is left is written at exit; a failure then goes unreported, as
    // it does in C.
    drop(stdout.flush());
    ending
}

fn run_all(line: &CommandLine<'_>, run: &Shared<'_, '_>) -> Ending {
    let msgs = run.msgs;
    // The result of the last transfer that ran.
    let mut last = Ok(());
    for op in &line.operations {
        if op.nodes.first().and_then(|n| n.url).is_none() {
            msgs.help(&[b"(2) no URL specified"]);
            return Ending::Done(Err(ErrorKind::FailedInit));
        }
        for (i, node) in op.nodes.iter().enumerate() {
            let Some(url) = node.url else {
                msgs.warn(&[b"Got more output options than URLs"]);
                break;
            };
            match transfer(op, run, node, url, i == 0) {
                Step::Ran(result) => {
                    last = result;
                    if result.is_err_and(fatal) {
                        return Ending::Done(result);
                    }
                }
                Step::Failed(e) => return Ending::Done(Err(e)),
                Step::Unopened(e) => return Ending::Done(last.and(Err(e))),
                Step::NotImplemented(what) => return Ending::NotImplemented(what),
            }
        }
    }
    Ending::Done(last)
}

/// Errors after which nothing more is tried (`is_fatal_error`).
fn fatal(e: ErrorKind) -> bool {
    matches!(
        e,
        ErrorKind::FailedInit
            | ErrorKind::OutOfMemory
            | ErrorKind::UnknownOption
            | ErrorKind::BadFunctionArgument
    )
}

/// What every transfer of the run shares.
struct Shared<'a, 'l> {
    global: &'a Global<'l>,
    stdout: &'a Stdout,
    tracer: Option<&'a Tracer>,
    msgs: Messages,
}

/// Set up, run and finish one URL's transfer (`create_single`,
/// `pre_transfer`, the perform and `post_per_transfer`); `first` is the
/// operation's first.
fn transfer(
    op: &Operation<'_>,
    run: &Shared<'_, '_>,
    node: &Node<'_>,
    url: &[u8],
    first: bool,
) -> Step {
    let msgs = run.msgs;
    let upload = match node.upload {
        Upload::File(file) => Some(file),
        Upload::Unset | Upload::Nothing => None,
    };
    // An upload is a PUT, which no other method may be chosen with.
    if upload.is_some() && op.method.allows(tool::Method::Put, &msgs).is_err() {
        return Step::Failed(ErrorKind::FailedInit);
    }
    let to_stdout = matches!(node.output, Output::Unset | Output::File(b"-"));
    let made = match node.output {
        Output::Null => output::Output::null(msgs),
        _ if to_stdout => output::Output::stdout(run.stdout, msgs),
        Output::File(name) => output::Output::file(name, msgs),
        Output::Unset => unreachable!("standard output"),
    };
    let Ok(out) = made else {
        return Step::Failed(ErrorKind::OutOfMemory);
    };
    let mut easy = Easy::new();
    // From here the transfer exists: a failure to set it up is its
    // result, and is finished as one (`run_all_transfers`'s cleanup).
    let failed = |easy: &Easy, e| {
        let result = finish(op, run, url, easy, &out, Err(e), false);
        Step::Failed(result.expect_err("a failure stays one"))
    };
    // `setup_headerfile`.
    if let Some(name) = op.dump_header {
        match out.dump_to(name, first, run.stdout) {
            Ok(()) => {}
            Err(output::DumpFailed::OutOfMemory) => return failed(&easy, ErrorKind::OutOfMemory),
            Err(output::DumpFailed::Open) => return failed(&easy, ErrorKind::WriteError),
        }
    }
    // Where the transfer starts (`setup_outfile`, `setup_transfer_upload`).
    let mut resume_from = match op.resume {
        Some(Resume::At(n)) => Some(n),
        Some(Resume::FromOutput) | None => None,
    };
    let mut skip = false;
    if let Output::File(name) = node.output
        && !to_stdout
    {
        let exists = std::fs::metadata(OsStr::from_bytes(name));
        if op.skip_existing && exists.is_ok() {
            msgs.note(&[b"skips transfer, \"", name, b"\" exists locally"]);
            skip = true;
        }
        if op.resume == Some(Resume::FromOutput) {
            resume_from = exists.as_ref().ok().map(|m| m.len());
        }
        if resume_from.is_some_and(|n| n > 0) && !out.stream().open_to_append() {
            return failed(&easy, ErrorKind::WriteError);
        }
    }
    if upload.is_some() {
        match needs_file_name(url) {
            Ok(false) => {}
            Ok(true) => return Step::NotImplemented("uploading to a URL without a file name"),
            Err(e) => return failed(&easy, e),
        }
    }
    let resume = if upload.is_some() && op.resume == Some(Resume::FromOutput) {
        Some(options::Resume::AtEnd)
    } else {
        resume_from
            .and_then(NonZeroU64::new)
            .map(options::Resume::At)
    };
    // Output to a terminal: no progress meter, and no binary output.
    let terminal = to_stdout && output_expected(url, upload.is_some()) && stdout_is_terminal();
    {
        let mut stream = out.stream();
        stream.show_headers = op.show_headers;
        stream.terminal = terminal;
        stream.binary_ok = node.output == Output::File(b"-");
        stream.no_buffer = op.no_buffer;
    }
    let config = Config {
        url,
        resume,
        upload: upload.is_some(),
        terminal,
    };
    if configure(&mut easy, op, run, &out, &config).is_err() {
        return failed(&easy, ErrorKind::OutOfMemory);
    }
    let result = if skip {
        Ok(())
    } else {
        if let Some(file) = upload {
            match open_upload(file) {
                Ok(source) => easy.options_mut().upload = source,
                Err(Unopened::OutOfMemory) => return failed(&easy, ErrorKind::OutOfMemory),
                Err(Unopened::Io) => {
                    msgs.help(&[b"cannot open '", file, b"'"]);
                    let result =
                        finish(op, run, url, &easy, &out, Err(ErrorKind::ReadError), false);
                    return Step::Unopened(result.expect_err("a failure stays one"));
                }
            }
        }
        easy.perform().map_err(|e| e.kind())
    };
    Step::Ran(finish(op, run, url, &easy, &out, result, skip))
}

/// What one transfer is set up with, beyond its operation's options.
struct Config<'a> {
    url: &'a [u8],
    resume: Option<options::Resume>,
    upload: bool,
    /// Standard output is a terminal, and the output goes there.
    terminal: bool,
}

/// Set up the transfer of `config.url` as `config2setopts` sets it.
fn configure(
    easy: &mut Easy,
    op: &Operation<'_>,
    run: &Shared<'_, '_>,
    out: &output::Output,
    config: &Config<'_>,
) -> Result<(), OutOfMemory> {
    let o = easy.options_mut();
    o.set_url(Some(config.url))?;
    if let Some(protocol) = op.default_protocol {
        o.set_default_protocol(Some(protocol.name().as_bytes()))?;
    }
    if config.upload {
        o.method = Method::Upload;
    } else if op.no_body {
        o.method = Method::Head;
    }
    o.resume = config.resume;
    o.progress = if run.global.no_progress || run.msgs.silent || config.terminal {
        Progress::Off
    } else {
        Progress::Meter
    };
    if let Some(tracer) = run.tracer {
        o.output.verbose = true;
        o.callbacks.debug = Some(tracer.handler(config.terminal)?);
    }
    o.callbacks.write = Some(out.body_handler()?);
    o.callbacks.header = Some(out.header_handler()?);
    // `credentials_and_headers_setopts` and `http_setopts`.
    let http = &mut o.http;
    http.headers = options::UserHeaders::new(op.headers.iter().copied())?;
    http.referer = op.referer.map(copy).transpose()?;
    http.user_agent = Some(match op.user_agent {
        Some(agent) => copy(agent)?,
        None => copy(
            try_format(format_args!(
                "curl/{}",
                curl_core::version::version().version
            ))?
            .as_bytes(),
        )?,
    });
    if let Some(version) = op.http_version {
        http.version = match version {
            HttpVersion::Http10 => options::HttpVersion::Http10,
            HttpVersion::Http11 => options::HttpVersion::Http11,
        };
    }
    http.allow_09 = op.http09;
    http.raw = op.raw;
    http.ignore_content_length = op.ignore_content_length;
    http.fail_on_error = op.fail;
    o.limits.max_filesize = NonZeroU64::new(op.max_filesize);
    o.limits.total = TimeLimit::from_millis(op.timeout_ms);
    o.limits.connect = TimeLimit::from_millis(op.connect_timeout_ms);
    Ok(())
}

/// `bytes`, owned.
fn copy(bytes: &[u8]) -> Result<Vec<u8>, OutOfMemory> {
    let mut owned = Vec::new();
    owned.try_extend_from_slice(bytes)?;
    Ok(owned)
}

/// What is done after a transfer, run or skipped, whatever its result
/// (`post_per_transfer`): its result reported, its output finished, its
/// `--write-out` written. Gives the result as it ends up.
fn finish(
    op: &Operation<'_>,
    run: &Shared<'_, '_>,
    url: &[u8],
    easy: &Easy,
    out: &output::Output,
    mut result: Result<(), ErrorKind>,
    skipped: bool,
) -> Result<(), ErrorKind> {
    let msgs = run.msgs;
    if !skipped {
        // `post_check_result`: the transfer's reason, or the kind's.
        if let Err(e) = result
            && let Ok(code) = try_format(format_args!("curl: ({}) ", exit_code(e)))
        {
            match easy.report().failure() {
                Some(why) => msgs.error_line(&[code.as_bytes(), why, b"\n"]),
                None => {
                    if let Ok(why) = try_format(format_args!("{e}\n")) {
                        msgs.error_line(&[code.as_bytes(), why.as_bytes()]);
                    }
                }
            }
        }
        let mut stream = out.stream();
        // `post_output_handling`: a successful transfer that wrote nothing
        // still leaves its output file, empty.
        if result.is_ok() && !stream.create() {
            result = Err(ErrorKind::WriteError);
        }
        if stream.flush().is_err() && result.is_ok() {
            msgs.error(&[b"Failed writing body"]);
            result = Err(ErrorKind::WriteError);
        }
        if result.is_ok()
            && op.remote_time
            && let Some(name) = stream.file_name()
            && let Some(t) = easy.report().filetime()
        {
            set_file_time(name, t, msgs);
        }
    }
    if let Some(format) = op.write_out {
        let stream = out.stream();
        let facts = Facts {
            exit_code: result.err().map_or(0, exit_code),
            url,
            filename: stream.file_name(),
            size_download: easy.report().sizes().download(),
            size_header: easy.report().sizes().header(),
            size_upload: easy.report().sizes().upload(),
        };
        write_out::write(format, &facts, run.stdout);
    }
    result
}

/// Give `name` the modification and access time `t`, seconds after the
/// epoch (`setfiletime`). A failure is only warned about.
fn set_file_time(name: &[u8], t: i64, msgs: Messages) {
    let at = if t >= 0 {
        UNIX_EPOCH.checked_add(Duration::from_secs(t.unsigned_abs()))
    } else {
        UNIX_EPOCH.checked_sub(Duration::from_secs(t.unsigned_abs()))
    };
    let set = at
        .ok_or_else(|| std::io::Error::from(std::io::ErrorKind::InvalidInput))
        .and_then(|at| {
            let times = FileTimes::new().set_accessed(at).set_modified(at);
            File::open(OsStr::from_bytes(name))?.set_times(times)
        });
    if let Err(e) = set {
        let reason = os_message(&e);
        if let Ok(number) = try_format(format_args!("{t}")) {
            msgs.warn(&[
                b"Failed to set filetime ",
                number.as_bytes(),
                b" on '",
                name,
                b"': ",
                reason.as_bytes(),
            ]);
        }
    }
}

/// Whether the transfer has output to show (`output_expected`): any
/// download, and an upload over HTTP.
fn output_expected(url: &[u8], upload: bool) -> bool {
    let prefixed = |p: &[u8]| url.len() >= p.len() && url[..p.len()].eq_ignore_ascii_case(p);
    !upload || prefixed(b"http://") || prefixed(b"https://")
}

/// Whether standard output is a terminal. The debug test build takes
/// `CURL_ISATTY` to say it is (`stream_isatty`).
fn stdout_is_terminal() -> bool {
    #[cfg(feature = "debug-hooks")]
    if std::env::var_os("CURL_ISATTY").is_some() {
        return true;
    }
    std::io::stdout().is_terminal()
}

/// Whether an upload to `url` needs the local file's name added to its
/// path, which ends without one (`add_file_name_to_url`).
fn needs_file_name(url: &[u8]) -> Result<bool, ErrorKind> {
    let parse = ParseOptions {
        guess_scheme: true,
        non_support_scheme: true,
        ..ParseOptions::NONE
    };
    let url = Url::parse(url, parse).map_err(url_error)?;
    let path = url.get(Part::Path, GetOptions::NONE).map_err(url_error)?;
    match url.get(Part::Query, GetOptions::NONE) {
        Ok(_) => return Ok(false),
        Err(UrlErrorKind::OutOfMemory) => return Err(ErrorKind::OutOfMemory),
        Err(_) => {}
    }
    Ok(path.last().is_none_or(|&b| b == b'/') || !path.contains(&b'/'))
}

/// A URL's error as the tool's (`urlerr_cvt`).
fn url_error(e: UrlErrorKind) -> ErrorKind {
    match e {
        UrlErrorKind::OutOfMemory => ErrorKind::OutOfMemory,
        UrlErrorKind::UnsupportedScheme => ErrorKind::UnsupportedProtocol,
        UrlErrorKind::LacksIdn => ErrorKind::NotBuiltIn,
        UrlErrorKind::BadHandle => ErrorKind::BadFunctionArgument,
        _ => ErrorKind::UrlMalformat,
    }
}

enum Unopened {
    Io,
    OutOfMemory,
}

/// The file to upload, opened, with its size if it is a regular file.
fn open_upload(name: &[u8]) -> Result<UploadSource, Unopened> {
    let file = File::open(OsStr::from_bytes(name)).map_err(|_| Unopened::Io)?;
    let meta = file.metadata().map_err(|_| Unopened::Io)?;
    let size = meta.is_file().then_some(meta.len());
    let file = curl_alloc::TryRc::try_new(std::cell::RefCell::new(file))
        .map_err(|_| Unopened::OutOfMemory)?;
    let handler = Handler::read(UploadFile(file.clone())).map_err(|_| Unopened::OutOfMemory)?;
    let rewind = Handler::rewind(UploadFile(file)).map_err(|_| Unopened::OutOfMemory)?;
    Ok(UploadSource::Read {
        handler,
        rewind: Some(rewind),
        size,
    })
}

/// Reads the file to upload (`tool_read_cb`), and starts it over
/// (`tool_seek_cb`).
struct UploadFile(curl_alloc::TryRc<std::cell::RefCell<File>>);

impl ReadHandler for UploadFile {
    fn read(&self, _: &mut TransferCx<'_>, buf: &mut [u8]) -> Read {
        // C takes a failed read for the end of the file; here it fails
        // the transfer rather than send part of the file as all of it.
        match self.0.borrow_mut().read(buf) {
            Ok(n) => NonZeroUsize::new(n).map_or(Read::Eof, Read::Data),
            Err(_) => Read::Abort,
        }
    }
}

impl Rewind for UploadFile {
    fn rewind(&self, _: &mut TransferCx<'_>) -> Result<(), RewindFailed> {
        match self.0.borrow_mut().seek(SeekFrom::Start(0)) {
            Ok(_) => Ok(()),
            Err(_) => Err(RewindFailed),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// C's `is_fatal_error`.
    #[test]
    fn stops_at_fatal_errors() {
        for e in [
            ErrorKind::FailedInit,
            ErrorKind::OutOfMemory,
            ErrorKind::UnknownOption,
            ErrorKind::BadFunctionArgument,
        ] {
            assert!(fatal(e), "{e:?}");
        }
        assert!(!fatal(ErrorKind::WriteError));
        assert!(!fatal(ErrorKind::FileCouldntReadFile));
    }

    #[test]
    fn expects_output_of_downloads_and_http_uploads() {
        assert!(output_expected(b"file:///f", false));
        assert!(!output_expected(b"file:///f", true));
        assert!(output_expected(b"HTTP://h/f", true));
        assert!(output_expected(b"https://h/f", true));
        assert!(!output_expected(b"http:/", true));
        assert!(!output_expected(b"https:/", true));
    }

    /// `add_file_name_to_url`: a path that ends in `/`, or has none, takes
    /// the file's name; a query keeps the URL as it is.
    #[test]
    fn adds_a_file_name_to_a_bare_path() {
        assert_eq!(needs_file_name(b"file:///dir/"), Ok(true));
        assert_eq!(needs_file_name(b"file:///dir/f"), Ok(false));
        assert_eq!(needs_file_name(b"file:///dir/?q"), Ok(false));
        assert_eq!(needs_file_name(b"http://host"), Ok(true));
        // Without a scheme one is guessed; one not supported is still read.
        assert_eq!(needs_file_name(b"host/dir/"), Ok(true));
        assert_eq!(needs_file_name(b"nosuch://host/f"), Ok(false));
        assert_eq!(
            needs_file_name(b"http://[bad/"),
            Err(ErrorKind::UrlMalformat)
        );
    }

    /// `urlerr_cvt`.
    #[test]
    fn maps_url_errors_as_c() {
        for (e, want) in [
            (UrlErrorKind::OutOfMemory, ErrorKind::OutOfMemory),
            (
                UrlErrorKind::UnsupportedScheme,
                ErrorKind::UnsupportedProtocol,
            ),
            (UrlErrorKind::LacksIdn, ErrorKind::NotBuiltIn),
            (UrlErrorKind::BadHandle, ErrorKind::BadFunctionArgument),
            (UrlErrorKind::MalformedInput, ErrorKind::UrlMalformat),
        ] {
            assert_eq!(url_error(e), want, "{e:?}");
        }
    }
}
