//! Running what the command line asks for: each URL's transfer, one after
//! another (`src/tool_operate.c`, its serial path).

use std::ffi::OsStr;
use std::fs::{File, FileTimes};
use std::io::{IsTerminal as _, Read as _, Seek as _, SeekFrom};
use std::num::{NonZeroU64, NonZeroUsize};
use std::os::unix::ffi::OsStrExt as _;
use std::time::{Duration, UNIX_EPOCH};

use curl_alloc::{OutOfMemory, try_format};
use curl_core::easy::Easy;
use curl_core::error::{ErrorKind, UrlErrorKind};
use curl_core::handler::{Handler, Read, ReadHandler, Rewind, RewindFailed};
use curl_core::multi::TransferCx;
use curl_core::options::{self, Method, Progress, UploadSource};
use curl_core::url::{GetOptions, ParseOptions, Part, Url};

use crate::msgs::Messages;
use crate::options::{CommandLine, Global, Node, Operation, Output, Resume, Upload, exit_code};
use crate::os_message;
use crate::output;
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
    let tracer = match Tracer::new(&line.global) {
        Ok(tracer) => tracer,
        Err(OutOfMemory) => return Ending::Done(Err(ErrorKind::OutOfMemory)),
    };
    // The result of the last transfer that ran.
    let mut last = Ok(());
    for op in &line.operations {
        if op.nodes.first().and_then(|n| n.url).is_none() {
            msgs.help(&[b"(2) no URL specified"]);
            return Ending::Done(Err(ErrorKind::FailedInit));
        }
        for node in &op.nodes {
            let Some(url) = node.url else {
                msgs.warn(&[b"Got more output options than URLs"]);
                break;
            };
            match transfer(op, &line.global, tracer.as_ref(), node, url, msgs) {
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

/// Set up, run and finish one URL's transfer (`create_single`,
/// `pre_transfer`, the perform and `post_per_transfer`).
fn transfer(
    op: &Operation<'_>,
    global: &Global<'_>,
    tracer: Option<&Tracer>,
    node: &Node<'_>,
    url: &[u8],
    msgs: Messages,
) -> Step {
    let upload = match node.upload {
        Upload::File(file) => Some(file),
        Upload::Unset | Upload::Nothing => None,
    };
    if upload.is_some() {
        match needs_file_name(url) {
            Ok(false) => {}
            Ok(true) => return Step::NotImplemented("uploading to a URL without a file name"),
            Err(e) => return Step::Failed(e),
        }
    }
    let to_stdout = matches!(node.output, Output::Unset | Output::File(b"-"));
    let made = match node.output {
        Output::Null => output::Output::null(msgs),
        _ if to_stdout => output::Output::stdout(msgs),
        Output::File(name) => output::Output::file(name, msgs),
        Output::Unset => unreachable!("standard output"),
    };
    let Ok(out) = made else {
        return Step::Failed(ErrorKind::OutOfMemory);
    };
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
            return Step::Failed(ErrorKind::WriteError);
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
    }
    let mut easy = match configure(
        op,
        global,
        tracer,
        url,
        &out,
        resume,
        upload.is_some(),
        terminal,
        msgs,
    ) {
        Ok(easy) => easy,
        Err(OutOfMemory) => return Step::Failed(ErrorKind::OutOfMemory),
    };
    let result = if skip {
        Ok(())
    } else {
        if let Some(file) = upload {
            match open_upload(file) {
                Ok(source) => easy.options_mut().upload = source,
                Err(Unopened::OutOfMemory) => return Step::Failed(ErrorKind::OutOfMemory),
                Err(Unopened::Io) => {
                    msgs.help(&[b"cannot open '", file, b"'"]);
                    let result =
                        finish(op, url, &easy, &out, Err(ErrorKind::ReadError), false, msgs);
                    return Step::Unopened(result.expect_err("a failure stays one"));
                }
            }
        }
        easy.perform().map_err(|e| e.kind())
    };
    Step::Ran(finish(op, url, &easy, &out, result, skip, msgs))
}

/// The transfer of `url`, set up as `config2setopts` sets it.
#[allow(
    clippy::too_many_arguments,
    reason = "C's per-transfer state, taken apart"
)]
fn configure(
    op: &Operation<'_>,
    global: &Global<'_>,
    tracer: Option<&Tracer>,
    url: &[u8],
    out: &output::Output,
    resume: Option<options::Resume>,
    upload: bool,
    terminal: bool,
    msgs: Messages,
) -> Result<Easy, OutOfMemory> {
    let mut easy = Easy::new();
    let o = easy.options_mut();
    o.set_url(Some(url))?;
    if let Some(protocol) = op.default_protocol {
        o.set_default_protocol(Some(protocol.name().as_bytes()))?;
    }
    if upload {
        o.method = Method::Upload;
    }
    o.resume = resume;
    o.progress = if global.no_progress || msgs.silent || terminal {
        Progress::Off
    } else {
        Progress::Meter
    };
    if let Some(tracer) = tracer {
        o.output.verbose = true;
        o.callbacks.debug = Some(tracer.handler(terminal)?);
    }
    o.callbacks.write = Some(out.body_handler()?);
    o.callbacks.header = Some(out.header_handler()?);
    Ok(easy)
}

/// What is done after a transfer, run or skipped, whatever its result
/// (`post_per_transfer`): its result reported, its output finished, its
/// `--write-out` written. Gives the result as it ends up.
fn finish(
    op: &Operation<'_>,
    url: &[u8],
    easy: &Easy,
    out: &output::Output,
    mut result: Result<(), ErrorKind>,
    skipped: bool,
    msgs: Messages,
) -> Result<(), ErrorKind> {
    if !skipped {
        // `post_check_result`.
        if let Err(e) = result {
            let code = exit_code(e);
            if let Ok(line) = try_format(format_args!("curl: ({code}) {e}\n")) {
                msgs.error_line(&[line.as_bytes()]);
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
        // `post_close_output`.
        stream.close();
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
            size_upload: easy.report().sizes().upload(),
        };
        write_out::write(format, &facts);
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
