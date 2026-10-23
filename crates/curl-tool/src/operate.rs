//! Running what the command line asks for: each URL's transfer, one after
//! another (`src/tool_operate.c`, its serial path).

use std::borrow::Cow;
use std::fs::File;
use std::io::{IsTerminal as _, Read as _, Seek as _, SeekFrom, Write as _};
use std::num::{NonZeroU64, NonZeroUsize};
use std::ops::{Deref, DerefMut};
use std::time::{Duration, Instant};

use curl_alloc::{OutOfMemory, TryArc, TryVec as _, try_format};
use curl_core::cookie::Suffixes;
use curl_core::easy::Easy;
use curl_core::error::{ErrorKind, UrlErrorKind};
use curl_core::handler::{Handler, HeaderOrigin, Read, ReadHandler, Rewind, RewindFailed};
use curl_core::multi::TransferCx;
use curl_core::options::{self, Method, Progress, UploadSource};
use curl_core::report::Request as HeaderRequest;
use curl_core::share::{Kind, Share};
use curl_core::time::TimeLimit;
use curl_core::url::{GetOptions, ParseOptions, Part, SetOptions, Url};
use curl_core::version::Protocol;
use curl_os::fs;

use crate::bar::Bar;
use crate::glob::{self, Glob};
use crate::msgs::Messages;
use crate::options::{
    self as tool, CommandLine, Fail, Global, HttpVersion, Httpsig, IpVersion, Node, Operation,
    Output, Resume, Upload, exit_code,
};
use crate::os_message;
use crate::output;
use crate::stdout::Stdout;
use crate::trace::Tracer;
use crate::write_out::{self, Facts};

/// How running the command line ended: the last transfer's result,
/// unless a run was cut short.
pub(crate) type Ending = Result<(), ErrorKind>;

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
}

/// Ask for the missing passwords, then run every operation's transfers
/// in turn (`get_args`, `serial_transfers`).
pub(crate) fn run(line: &mut CommandLine<'_>, msgs: Messages) -> Ending {
    if ask_passwords(&mut line.operations).is_err() {
        return Err(ErrorKind::OutOfMemory);
    }
    let line = &*line;
    let Ok(stdout) = Stdout::new() else {
        return Err(ErrorKind::OutOfMemory);
    };
    let tracer = match Tracer::new(&line.global, &stdout) {
        Ok(tracer) => tracer,
        Err(OutOfMemory) => return Err(ErrorKind::OutOfMemory),
    };
    // The transfers share their connections, resolved names and cookies,
    // as C's tool gives each handle its share.
    let share = match Share::new() {
        Ok(share) => share,
        Err(OutOfMemory) => return Err(ErrorKind::OutOfMemory),
    };
    for kind in [Kind::Connections, Kind::Names, Kind::Cookies] {
        share.keep(kind).expect("held by none yet");
    }
    // And one list of public suffixes (`CURL_LOCK_DATA_PSL`).
    let suffixes = match curl_psl::suffixes() {
        Ok(suffixes) => suffixes,
        Err(OutOfMemory) => return Err(ErrorKind::OutOfMemory),
    };
    let run = Shared {
        global: &line.global,
        stdout: &stdout,
        tracer: tracer.as_ref(),
        msgs,
        share: &share,
        suffixes: &suffixes,
    };
    let ending = run_all(line, &run);
    // What is left is written at exit; a failure then goes unreported, as
    // it does in C.
    drop(stdout.flush());
    ending
}

/// The longest `user:password` a password asked for may make, less one
/// (`MAX_USERPWDLENGTH`, its terminating zero counted).
const MAX_LOGIN: usize = 100 * 1024;

/// The tool's read buffer (`BUFFER_SIZE`).
const TOOL_BUFFER: u64 = 102_400;

/// What a typed password is read into, its last byte the line's end
/// (`checkpasswd`'s buffer).
const PASSWORD_ROOM: usize = 2048;

/// The longest prompt, as C's buffer of 256 cuts it.
const MAX_PROMPT: usize = 255;

/// Ask for the password of each `-u` (unless `--oauth2-bearer`) and `-U`
/// given without one, every operation's in turn, before anything is
/// transferred (`get_args`).
fn ask_passwords(operations: &mut [Operation<'_>]) -> Result<(), OutOfMemory> {
    // Several operations number theirs in the prompt.
    let numbered = operations.len() > 1;
    for (i, op) in operations.iter_mut().enumerate() {
        let number = numbered.then_some(i + 1);
        if op.bearer.is_none() {
            ask_password(&mut op.user, b"host", number)?;
        }
        ask_password(&mut op.proxy_user, b"proxy", number)?;
    }
    Ok(())
}

/// Complete `login` with a password read from the terminal, or from
/// standard input without one, when it has none: no `:`, and not only
/// `;options` (`checkpasswd`). The prompt names the user without its
/// options, which stay where they were: `user;options:password`.
fn ask_password(
    login: &mut Option<Cow<'_, [u8]>>,
    kind: &[u8],
    number: Option<usize>,
) -> Result<(), OutOfMemory> {
    let Some(given) = login.as_deref() else {
        return Ok(());
    };
    if given.contains(&b':') || given.first() == Some(&b';') {
        return Ok(());
    }
    let user = given.split(|&b| b == b';').next().unwrap_or_default();
    let mut prompt = Vec::new();
    prompt.try_extend_from_slice(b"Enter ")?;
    prompt.try_extend_from_slice(kind)?;
    prompt.try_extend_from_slice(b" password for user '")?;
    prompt.try_extend_from_slice(user)?;
    prompt.try_extend_from_slice(b"'")?;
    if let Some(number) = number {
        prompt.try_extend_from_slice(try_format(format_args!(" on URL #{number}"))?.as_bytes())?;
    }
    prompt.try_extend_from_slice(b":")?;
    prompt.truncate(MAX_PROMPT);
    let mut typed = curl_os::terminal::Unechoed::open();
    // Unbuffered, and a failure has nowhere to be reported, as C's
    // `fputs` to `stderr`.
    let mut stderr = std::io::stderr();
    drop(stderr.write_all(&prompt));
    let mut buf = [0; PASSWORD_ROOM];
    let n = typed.read(&mut buf);
    // The last byte read is taken for the line's end, whatever it is, and
    // a zero byte ends the password as it ends C's string.
    let password = buf[..n.saturating_sub(1)]
        .split(|&b| b == 0)
        .next()
        .unwrap_or_default();
    // What was typed was not echoed, so the line is ended here; C ends it
    // whether or not echo could be turned off.
    drop(stderr.write_all(b"\n"));
    drop(typed);
    let len = given.len() + 1 + password.len();
    if len >= MAX_LOGIN {
        return Err(OutOfMemory);
    }
    let mut whole = Vec::new();
    whole.try_reserve_exact(len)?;
    whole.try_extend_from_slice(given)?;
    whole.try_push(b':')?;
    whole.try_extend_from_slice(password)?;
    *login = Some(Cow::Owned(whole));
    Ok(())
}

fn run_all(line: &CommandLine<'_>, run: &Shared<'_, '_>) -> Ending {
    let msgs = run.msgs;
    // The result of the last transfer that ran.
    let mut last = Ok(());
    // Each URL's number on the command line, across operations
    // (`outnum`).
    let mut urlnum = 0;
    for op in &line.operations {
        if op.nodes.first().and_then(|n| n.url).is_none() {
            msgs.help(&[b"(2) no URL specified"]);
            return Err(ErrorKind::FailedInit);
        }
        let mut first = true;
        for node in &op.nodes {
            let Some(url) = node.url else {
                msgs.warn(&[b"Got more output options than URLs"]);
                break;
            };
            let given = Given {
                text: url,
                num: urlnum,
            };
            urlnum += 1;
            if let Some(ending) = node_transfers(op, run, node, given, &mut first, &mut last) {
                return ending;
            }
        }
    }
    last
}

/// Run a node's transfers: one for each file its upload pattern names,
/// times each URL its URL pattern makes, the URL's changing first
/// (`create_single`). Each has the node's number. `None` if the
/// operation goes on.
fn node_transfers(
    op: &Operation<'_>,
    run: &Shared<'_, '_>,
    node: &Node<'_>,
    given: Given<'_>,
    first: &mut bool,
    last: &mut Result<(), ErrorKind>,
) -> Option<Ending> {
    let msgs = run.msgs;
    // A name without patterns still names an output through one, unless
    // globbing is off (`glob_inuse` is true of a literal).
    let literal = Glob::literal();
    let expand = |text: &[u8], literal: bool| -> Result<Option<Glob>, Ending> {
        if op.globoff || literal || !glob::has_patterns(text) {
            return Ok(None);
        }
        match Glob::parse(text) {
            Ok((parsed, _)) => Ok(Some(parsed)),
            Err(e) => {
                e.show(text, &msgs);
                Err(Err(e.kind))
            }
        }
    };
    let file = match node.upload {
        Upload::File(file) => Some(file),
        Upload::Unset | Upload::Nothing => None,
    };
    // `setup_input_file`.
    let mut uploads = match file.map(|file| expand(file, false)).transpose() {
        Ok(uploads) => uploads.flatten(),
        Err(ending) => return Some(ending),
    };
    let next = |glob: &mut Option<Glob>, whole: Option<&[u8]>, held: &mut Vec<u8>| match glob {
        Some(glob) => match glob.next_url() {
            Ok(Some(next)) => {
                *held = next;
                Ok(Some(true))
            }
            Ok(None) => Ok(None),
            Err(OutOfMemory) => Err(Err(ErrorKind::OutOfMemory)),
        },
        None => Ok(whole.map(|_| false)),
    };
    let mut upload_held = Vec::new();
    let mut upload_once = true;
    loop {
        let upload = match next(&mut uploads, Some(b""), &mut upload_held) {
            Ok(Some(true)) => Some(&upload_held[..]),
            Ok(Some(false)) if std::mem::take(&mut upload_once) => file,
            Ok(_) => break,
            Err(ending) => return Some(ending),
        };
        // `setup_url_pattern`, again for each upload.
        // A URL read from a file is not globbed (`noglob`).
        let mut urls = match expand(given.text, node.literal) {
            Ok(urls) => urls,
            Err(ending) => return Some(ending),
        };
        let mut url_held = Vec::new();
        let mut url_once = true;
        loop {
            let text = match next(&mut urls, Some(b""), &mut url_held) {
                Ok(Some(true)) => &url_held[..],
                Ok(Some(false)) if std::mem::take(&mut url_once) => given.text,
                Ok(_) => break,
                Err(ending) => return Some(ending),
            };
            let this = Given { text, ..given };
            // Names read the patterns while one is in use (`glob_inuse`).
            let names = (!op.globoff && (!node.literal || file.is_some())).then(|| Names {
                url: urls.as_ref().unwrap_or(&literal),
                upload: uploads.as_ref(),
            });
            let step = transfer(op, run, node, this, upload, names, *first);
            *first = false;
            match step {
                Step::Ran(result) => {
                    *last = result;
                    if result.is_err_and(fatal) {
                        return Some(result);
                    }
                }
                Step::Failed(e) => return Some(Err(e)),
                Step::Unopened(e) => return Some(last.and(Err(e))),
            }
        }
    }
    None
}

/// Make each directory `path`, a file's name, is in that is not there
/// yet, with permissions `rwxr-x---` (`create_dir_hierarchy`). One that
/// exists, or that may not be looked at, is gone through.
fn create_dirs(path: &[u8], msgs: &Messages) -> Result<(), ErrorKind> {
    use std::io::ErrorKind as Io;
    let mut at = 0;
    loop {
        let seps = path[at..].iter().take_while(|&&b| b == b'/').count();
        let name = path[at + seps..].iter().take_while(|&&b| b != b'/').count();
        at += seps + name;
        // The last part is the file.
        if at == path.len() {
            return Ok(());
        }
        let dir = &path[..at];
        let Err(e) = fs::with_c_name(dir, |c| fs::make_dir(c, 0o750)) else {
            continue;
        };
        if e.kind() == Io::AlreadyExists || curl_os::fs::denied(&e) {
            continue;
        }
        msgs.error(&dir_error(e.kind(), dir));
        return Err(ErrorKind::WriteError);
    }
}

/// What is said of `dir` that could not be made, for the reason `kind`
/// (`show_dir_errno`).
fn dir_error(kind: std::io::ErrorKind, dir: &[u8]) -> [&[u8]; 3] {
    use std::io::ErrorKind as Io;
    match kind {
        Io::InvalidFilename => [b"The directory name ", dir, b" is too long"],
        Io::ReadOnlyFilesystem => [dir, b" resides on a read-only file system", b""],
        Io::StorageFull => [
            b"No space left on the file system that would contain the directory ",
            dir,
            b"",
        ],
        Io::QuotaExceeded => [
            b"Cannot create directory ",
            dir,
            b" because you exceeded your quota",
        ],
        _ => [b"Error creating directory ", dir, b""],
    }
}

/// `dir/name`.
fn joined(dir: &[u8], name: &[u8]) -> Result<Vec<u8>, OutOfMemory> {
    let mut path = Vec::new();
    path.try_reserve_exact(dir.len() + 1 + name.len())?;
    path.try_extend_from_slice(dir)?;
    path.try_push(b'/')?;
    path.try_extend_from_slice(name)?;
    Ok(path)
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

/// A URL as the command line gives it, and its number there.
#[derive(Clone, Copy)]
struct Given<'a> {
    text: &'a [u8],
    num: u64,
}

/// The patterns an output name reads: the URL's, or a literal one for a
/// URL without, and the upload file's.
#[derive(Clone, Copy)]
struct Names<'a> {
    url: &'a Glob,
    upload: Option<&'a Glob>,
}

/// What every transfer of the run shares.
struct Shared<'a, 'l> {
    global: &'a Global<'l>,
    stdout: &'a Stdout,
    tracer: Option<&'a Tracer>,
    msgs: Messages,
    share: &'a Share,
    suffixes: &'a Suffixes,
}

/// Set up, run and finish one URL's transfer (`create_single`,
/// `pre_transfer`, the perform and `post_per_transfer`); `first` is the
/// operation's first.
fn transfer(
    op: &Operation<'_>,
    run: &Shared<'_, '_>,
    node: &Node<'_>,
    given: Given<'_>,
    upload: Option<&[u8]>,
    names: Option<Names<'_>>,
    first: bool,
) -> Step {
    let msgs = run.msgs;
    let url = given.text;
    // The data of `--data` makes a POST, an upload a PUT, and no other
    // method may be chosen with either (`single_transfer`,
    // `create_single`).
    // With `--get` the data goes in the URL's query instead, asked for
    // with a GET, or a HEAD after `--head`.
    let mut method = op.method;
    let (post, fields) = match op.post.as_deref() {
        Some(fields) if op.get => (None, Some(fields)),
        post => (post, None),
    };
    let wanted = match (post, fields) {
        (Some(_), _) => Some(tool::Method::Post),
        (None, Some(_)) if op.no_body => Some(tool::Method::Head),
        (None, Some(_)) => Some(tool::Method::Get),
        (None, None) => None,
    };
    if wanted.is_some_and(|wanted| method.choose(wanted, &msgs).is_err()) {
        return Step::Failed(ErrorKind::FailedInit);
    }
    // `--url-query` gives the query otherwise.
    let query = fields.or(op.url_query.as_deref());
    if upload.is_some() && method.choose(tool::Method::Put, &msgs).is_err() {
        return Step::Failed(ErrorKind::FailedInit);
    }
    // `check_post_resume`: data is not resumed, and C says so itself.
    let resumed = match op.resume {
        Some(Resume::FromOutput) => true,
        Some(Resume::At(n)) => n > 0,
        None => false,
    };
    if matches!(method, tool::Method::Post | tool::Method::Mime) && resumed {
        msgs.error(&[b"(43) HTTP upload cannot be resumed"]);
        return Step::Failed(ErrorKind::BadFunctionArgument);
    }
    // Where the output goes (`setup_outfile`): a file the URL names, for
    // `--remote-name`, is never standard output.
    let output = match node.output {
        Output::Unset if node.remote => Output::Remote,
        output => output,
    };
    let output_is_remote = output == Output::Remote;
    let to_stdout = matches!(output, Output::Unset | Output::Stdout | Output::File(b"-"));
    // A name given reads the URL's patterns (`glob_match_url`).
    let globbed;
    let output = match (output, names) {
        (Output::File(name), Some(names)) if !to_stdout => {
            globbed = match names.url.output_name(name, names.upload) {
                Ok(globbed) => globbed,
                Err(e) => {
                    e.show(name, &msgs);
                    return Step::Failed(e.kind);
                }
            };
            if globbed.is_empty() {
                msgs.warn(&[b"output glob produces empty string"]);
                return Step::Failed(ErrorKind::WriteError);
            }
            Output::File(&globbed)
        }
        (output, _) => output,
    };
    let remote_name;
    let output = match output {
        Output::Remote => {
            remote_name = match url_file_name(url, &msgs) {
                Ok(name) => name,
                Err(e) => {
                    msgs.error(&[b"Failed to extract a filename from the URL to use for storage"]);
                    return Step::Failed(e);
                }
            };
            Output::File(&remote_name)
        }
        output => output,
    };
    // A file goes in the output directory.
    let in_dir;
    let output = match (output, op.output_dir) {
        (Output::File(name), Some(dir)) if !to_stdout => {
            in_dir = match joined(dir, name) {
                Ok(path) => path,
                Err(OutOfMemory) => return Step::Failed(ErrorKind::OutOfMemory),
            };
            Output::File(&in_dir)
        }
        (output, _) => output,
    };
    let made = match output {
        Output::Null => output::Output::null(msgs),
        _ if to_stdout => output::Output::stdout(run.stdout, msgs),
        Output::File(name) => output::Output::file(name, msgs),
        Output::Unset | Output::Stdout | Output::Remote => unreachable!("standard output"),
    };
    let Ok(out) = made else {
        return Step::Failed(ErrorKind::OutOfMemory);
    };
    let mut easy = Handle(Easy::new());
    easy.set_share(Some(run.share.clone()));
    easy.set_public_suffixes(Some(run.suffixes.clone()));
    easy.set_decoders(decoders());
    // From here the transfer exists: a failure to set it up is its
    // result, and is finished as one (`run_all_transfers`'s cleanup).
    let failed = |easy: &Easy, e| {
        let result = finish(op, run, given, easy, &out, None, Ended::Ran(Err(e)));
        Step::Failed(result.expect_err("a failure stays one"))
    };
    // A failure the tool has said already (C's `synthetic_error`).
    let said = |easy: &Easy, e| {
        let result = finish(op, run, given, easy, &out, None, Ended::Said(e));
        Step::Failed(result.expect_err("a failure stays one"))
    };
    // `setup_headerfile`.
    if let Some(name) = op.dump_header {
        if op.create_dirs
            && name != b"-"
            && name != b"%"
            && let Err(e) = create_dirs(name, &msgs)
        {
            return failed(&easy, e);
        }
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
    if let Output::File(name) = output
        && !to_stdout
    {
        if op.create_dirs
            && let Err(e) = create_dirs(name, &msgs)
        {
            return failed(&easy, e);
        }
        let exists = fs::with_c_name(name, fs::stat);
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
    // An upload to a path without a name gives it the file's; standard
    // input names none (`setup_transfer_upload`, `stdin_upload`).
    let named;
    let given = match upload.filter(|&file| file != b"-") {
        Some(file) => match with_file_name(url, file) {
            Ok(Some(url)) => {
                named = url;
                Given {
                    text: &named,
                    ..given
                }
            }
            Ok(None) => given,
            Err(e) => return failed(&easy, e),
        },
        None => given,
    };
    let url = given.text;
    let resume = if upload.is_some() && op.resume == Some(Resume::FromOutput) {
        Some(options::Resume::AtEnd)
    } else {
        resume_from
            .and_then(NonZeroU64::new)
            .map(options::Resume::At)
    };
    // Output to a terminal: no progress meter, and no binary output.
    let terminal = to_stdout && output_expected(url, upload.is_some()) && stdout_is_terminal();
    // The query `--get` or `--url-query` makes is added once the output
    // and the upload are named (`append2query`).
    let queried;
    let given = match query.map(|query| with_query(url, query)) {
        Some(Ok(url)) => {
            queried = url;
            Given {
                text: &queried,
                ..given
            }
        }
        Some(Err(QueryFailed::Parse(e))) => {
            if let Ok(line) = try_format(format_args!(
                "({}) Could not parse the URL, failed to set query",
                exit_code(e)
            )) {
                msgs.error(&[line.as_bytes()]);
            }
            return said(&easy, e);
        }
        Some(Err(QueryFailed::Set(e))) => return failed(&easy, e),
        None => given,
    };
    let url = given.text;
    // Only a URL taken for HTTP's is given HTTP's options; one for IPFS
    // goes to its gateway, or nowhere, said once (`synthetic_error`).
    let (proto, parsed) = match url_proto(url, op.default_protocol) {
        Ok(found) => found,
        Err(OutOfMemory) => return failed(&easy, ErrorKind::OutOfMemory),
    };
    let rewritten;
    let given = match (proto, parsed) {
        (UrlProto::Ipfs(kind), Some(mut parsed)) => {
            match crate::ipfs::rewrite(&mut parsed, kind, op.ipfs_gateway) {
                Ok(url) => {
                    rewritten = url;
                    Given {
                        text: &rewritten,
                        ..given
                    }
                }
                Err(e) => {
                    let e = e.said(&msgs);
                    let result = finish(op, run, given, &easy, &out, None, Ended::Said(e));
                    return Step::Failed(result.expect_err("a failure stays one"));
                }
            }
        }
        _ => given,
    };
    let url = given.text;
    let http = proto == UrlProto::Http;
    {
        let mut stream = out.stream();
        stream.show_headers = op.show_headers;
        stream.terminal = terminal;
        stream.binary_ok = node.output == Output::File(b"-");
        stream.no_buffer = op.no_buffer;
        stream.clobber = op.clobber;
        // `--remote-header-name` names only a file `--remote-name` names
        // (`setup_header_cb`).
        if op.remote_header_name && output_is_remote {
            match output::FromHeader::new(op.output_dir) {
                Ok(from) => stream.name_from_header = Some(from),
                Err(OutOfMemory) => {
                    drop(stream);
                    return failed(&easy, ErrorKind::OutOfMemory);
                }
            }
        }
    }
    // A resumed transfer's bar shows the whole (`progressbarinit`); an
    // upload resumed at the end of what the peer holds learns it there.
    let bar = if run.global.progress_bar {
        let start = match resume {
            Some(options::Resume::AtEnd) => None,
            _ => Some(resume_from.unwrap_or(0)),
        };
        match Bar::new(start) {
            Ok(bar) => Some(bar),
            Err(OutOfMemory) => return failed(&easy, ErrorKind::OutOfMemory),
        }
    } else {
        None
    };
    // The tree `--form` gives, made for this transfer (`setopt_post`).
    let form = match (&op.form, method) {
        (Some(form), tool::Method::Mime) => match form.mime(&msgs) {
            Ok(mime) => match curl_alloc::TryArc::try_new(mime) {
                Ok(mime) => Some(mime),
                Err(OutOfMemory) => return failed(&easy, ErrorKind::OutOfMemory),
            },
            Err(e) => return failed(&easy, e),
        },
        _ => None,
    };
    let config = Config {
        url,
        http,
        resume,
        upload: upload.is_some(),
        post,
        form,
        method,
        terminal,
        bar: bar.as_ref(),
    };
    let cookies = match http.then(|| joined_cookies(&op.cookies, &run.msgs)) {
        Some(Ok(cookies)) => cookies,
        None => None,
        Some(Err(e)) => return failed(&easy, e),
    };
    if configure(&mut easy, op, run, &out, &config).is_err() {
        return failed(&easy, ErrorKind::OutOfMemory);
    }
    if http && let Err(e) = message_signature(easy.options_mut(), op.httpsig, &msgs) {
        return failed(&easy, e);
    }
    if let Some(pair) = op.proxy_user.as_deref() {
        let set = match easy.options_mut().proxy.make_mut() {
            Ok(proxy) => proxy.set_user_password(Some(pair)),
            Err(OutOfMemory) => Err(options::ProxyUserError::OutOfMemory),
        };
        if let Err(e) = set {
            let kind = match e {
                options::ProxyUserError::OutOfMemory => ErrorKind::OutOfMemory,
                options::ProxyUserError::Malformed => ErrorKind::UrlMalformat,
            };
            return failed(&easy, kind);
        }
    }
    if cookies.is_some() || easy.options().http.cookies.send.is_some() {
        match easy.options_mut().http.cookies.make_mut() {
            Ok(made) => made.send = cookies,
            Err(OutOfMemory) => return failed(&easy, ErrorKind::OutOfMemory),
        }
    }
    let ended = if skip {
        Ended::Skipped
    } else {
        let mut retrying = Retrying::new(op, resume_from);
        loop {
            // Opened for each attempt, from its start.
            if let Some(file) = upload {
                match open_upload(file) {
                    Ok(source) => easy.options_mut().upload = source,
                    Err(Unopened::OutOfMemory) => return failed(&easy, ErrorKind::OutOfMemory),
                    Err(Unopened::Io) => {
                        msgs.help(&[b"cannot open '", file, b"'"]);
                        let result = finish(
                            op,
                            run,
                            given,
                            &easy,
                            &out,
                            bar.as_ref(),
                            Ended::Ran(Err(ErrorKind::ReadError)),
                        );
                        return Step::Unopened(result.expect_err("a failure stays one"));
                    }
                }
            }
            #[cfg(feature = "debug-hooks")]
            let result = if run.global.test_event {
                easy.perform_ev()
            } else {
                easy.perform()
            };
            #[cfg(not(feature = "debug-hooks"))]
            let result = easy.perform();
            let result = result.map_err(|e| e.kind());
            let result = settle(op, msgs, &easy, &out, result, false);
            let attempt = Attempt {
                result,
                upload: upload.is_some(),
                method,
            };
            match retrying.check(op, msgs, &mut easy, &out, attempt) {
                Again::After(wait) => std::thread::sleep(wait),
                Again::No(result) => break Ended::Settled(result, retrying.retries),
            }
        }
    };
    Step::Ran(finish(op, run, given, &easy, &out, bar.as_ref(), ended))
}

/// A transfer's handle, which saves the cookie jar when it is done with,
/// as C's `curl_easy_cleanup` does (`Curl_flush_cookies`).
struct Handle(Easy);

impl Deref for Handle {
    type Target = Easy;

    fn deref(&self) -> &Easy {
        &self.0
    }
}

impl DerefMut for Handle {
    fn deref_mut(&mut self) -> &mut Easy {
        &mut self.0
    }
}

impl Drop for Handle {
    fn drop(&mut self) {
        // A failure goes unsaid: C's cleanup stops tracing before it saves
        // the jar, so its warning is never seen.
        let _unsaid = self.0.save_cookies();
    }
}

/// The longest wait between attempts, unless the server asks for more
/// (`RETRY_SLEEP_MAX`).
const RETRY_WAIT_MAX: u64 = 600_000;

/// The longest `--cookie` strings may be together, and a zero byte
/// (`MAX_REQUEST_COOKIE`).
const MAX_REQUEST_COOKIE: usize = 8200;

/// What `--retry` keeps across one transfer's attempts (C's
/// `per_transfer`'s `retry_*`).
struct Retrying {
    /// When the first attempt started.
    start: Instant,
    /// Attempts made again so far.
    retries: u64,
    /// The last wait, in milliseconds; 0 before the first.
    wait_ms: u64,
    /// Where the output file was resumed from, if it was.
    resumed_at: u64,
}

/// One attempt, as it ended.
struct Attempt {
    result: Result<(), ErrorKind>,
    upload: bool,
    method: tool::Method,
}

/// Whether to try again.
enum Again {
    /// After this long.
    After(Duration),
    /// No: the transfer ends with this result.
    No(Result<(), ErrorKind>),
}

/// The wait after `last`, with no wait given: a second first, then twice
/// the last, up to ten minutes.
fn backoff(last: u64) -> u64 {
    match last {
        0 => 1000,
        ms => ms.saturating_mul(2),
    }
    .min(RETRY_WAIT_MAX)
}

/// Why an attempt is tried again (C's `retryreason`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Reason {
    AllErrors,
    Timeout,
    Http,
}

impl Reason {
    fn text(self) -> &'static [u8] {
        match self {
            Reason::AllErrors => b"(retrying all errors)",
            Reason::Timeout => b": timeout",
            Reason::Http => b": HTTP error",
        }
    }
}

/// Why an attempt that ended with `result`, its last response `code` over
/// `protocol`, would be tried again, if it would (`retrycheck`): a failure
/// that may pass, an HTTP response saying so, or with `--retry-all-errors`
/// any failure. An FTP 4xx (`RETRY_FTP`) and a refused connection
/// (`RETRY_CONNREFUSED`) join with FTP and `--retry-connrefused`.
fn reason(
    op: &Operation<'_>,
    result: Result<(), ErrorKind>,
    protocol: Option<Protocol>,
    code: Option<u16>,
) -> Option<Reason> {
    let passing = matches!(
        result,
        Err(ErrorKind::OperationTimedout
            | ErrorKind::CouldntResolveHost
            | ErrorKind::CouldntResolveProxy
            | ErrorKind::FtpAcceptTimeout)
    );
    let failed_http = op.fail != Fail::Off && result == Err(ErrorKind::HttpReturnedError);
    let reason = if passing {
        Some(Reason::Timeout)
    } else if (result.is_ok() || failed_http)
        && protocol == Some(Protocol::Http)
        && matches!(code, Some(408 | 429 | 500 | 502 | 503 | 504 | 522 | 524))
    {
        Some(Reason::Http)
    } else {
        None
    };
    match reason {
        None if result.is_err() && op.retry_all_errors => Some(Reason::AllErrors),
        reason => reason,
    }
}

impl Retrying {
    fn new(op: &Operation<'_>, resumed_at: Option<u64>) -> Retrying {
        Retrying {
            start: Instant::now(),
            retries: 0,
            wait_ms: op.retry_delay_ms,
            resumed_at: resumed_at.unwrap_or(0),
        }
    }

    /// Whether to try `attempt` again, and after how long; the output
    /// readied for it (`post_per_transfer`'s part, `retrycheck`).
    fn check(
        &mut self,
        op: &Operation<'_>,
        msgs: Messages,
        easy: &mut Easy,
        out: &output::Output,
        attempt: Attempt,
    ) -> Again {
        let result = attempt.result;
        let elapsed = u64::try_from(self.start.elapsed().as_millis()).unwrap_or(u64::MAX);
        let max = op.retry_max_time_ms;
        if self.retries >= op.retry || (max > 0 && elapsed >= max) {
            return Again::No(result);
        }
        let report = easy.report();
        let Some(reason) = reason(op, result, report.protocol(), report.response_code()) else {
            return Again::No(result);
        };
        // `retry_sleep`: what the server asks for, or the wait given, or
        // one doubled each time from a second.
        let mut wait = 0;
        if reason == Reason::Http
            && let Some(after) = easy.report().retry_after().filter(|d| !d.is_zero())
        {
            wait = after
                .as_secs()
                .saturating_mul(1000)
                .min(u64::from(u32::MAX));
            if max > 0 && elapsed.saturating_add(wait) > max {
                msgs.warn(&[
                    b"The Retry-After: time would make this command line exceed \
                              the maximum allowed time for retries.",
                ]);
                return Again::No(result);
            }
        }
        if wait == 0 && op.retry_delay_ms == 0 {
            self.wait_ms = backoff(self.wait_ms);
        }
        if wait == 0 {
            wait = self.wait_ms;
        }
        let left = op.retry - self.retries;
        let (secs, ms) = (wait / 1000, wait % 1000);
        let told = if ms == 0 {
            try_format(format_args!("{secs}"))
        } else {
            try_format(format_args!("{secs}.{ms:03}"))
        };
        let counts = try_format(format_args!(
            " second{}. {left} retr{} left.",
            if wait == 1000 { "" } else { "s" },
            if left > 1 { "ies" } else { "y" }
        ));
        if let (Ok(told), Ok(counts)) = (told, counts) {
            msgs.warn(&[
                b"Problem ",
                reason.text(),
                b". Retrying in ",
                told.as_bytes(),
                counts.as_bytes(),
            ]);
        }
        let mut stream = out.stream();
        // What came of a GET that can be resumed is kept, and the next
        // attempt asks for the rest.
        if self.resumable(op, &stream, &attempt) && answered_resumably(easy, self.resumed_at) {
            if let Ok(n) = try_format(format_args!("{}", stream.written())) {
                msgs.note(&[b"Keeping ", n.as_bytes(), b" bytes"]);
            }
            if stream.flush().is_err() {
                msgs.error(&[b"Failed to flush output file stream"]);
                return Again::No(Err(ErrorKind::WriteError));
            }
            let Some(at) = stream.keep() else {
                if let Ok(why) = try_format(format_args!(
                    "Exceeded maximum supported file size ({} + {})",
                    stream.start(),
                    stream.written()
                )) {
                    msgs.error(&[why.as_bytes()]);
                }
                return Again::No(Err(ErrorKind::WriteError));
            };
            self.resumed_at = at;
            easy.options_mut().resume = NonZeroU64::new(at).map(options::Resume::At);
        } else if !stream.throw_away() {
            return Again::No(Err(ErrorKind::WriteError));
        }
        self.retries += 1;
        Again::After(Duration::from_millis(wait))
    }

    /// Whether what `attempt` wrote may be kept and resumed from
    /// (`is_outfile_auto_resumable`): a GET resuming its output file, which
    /// it wrote to and wrote all it was given of.
    fn resumable(&self, op: &Operation<'_>, stream: &output::Stream, attempt: &Attempt) -> bool {
        op.resume == Some(Resume::FromOutput)
            && stream.start() == self.resumed_at
            && stream.written() > 0
            && stream.is_open_file()
            && !stream.failed()
            && op.custom_request.is_none()
            && !attempt.upload
            && matches!(attempt.method, tool::Method::Unset | tool::Method::Get)
            && !matches!(
                attempt.result,
                Err(ErrorKind::WriteError | ErrorKind::RangeError)
            )
    }
}

/// The response of `easy`'s attempt says the next may ask for the rest: a
/// GET answered with a range asked for, or with a whole that says ranges
/// may be (`retrycheck`).
fn answered_resumably(easy: &Easy, resumed_at: u64) -> bool {
    let report = easy.report();
    if report.protocol() != Some(Protocol::Http) || easy.effective_method() != b"GET" {
        return false;
    }
    match report.response_code() {
        Some(206) => resumed_at > 0,
        Some(200) => report
            .headers()
            .get(
                b"Accept-Ranges",
                0,
                HeaderOrigin::Header.into(),
                HeaderRequest::Last,
            )
            .is_ok_and(|h| h.value == b"bytes"),
        _ => false,
    }
}

/// How a transfer ended.
#[derive(Clone, Copy)]
enum Ended {
    /// With this result, from the library.
    Ran(Result<(), ErrorKind>),
    /// With this result, settled, after this many retries.
    Settled(Result<(), ErrorKind>, u64),
    /// Never started: its output file exists (`--skip-existing`). It
    /// succeeds, and only its `--write-out` is written.
    Skipped,
    /// Not set up, for a reason the tool has said itself: it is not said
    /// again (C's `synthetic_error`).
    Said(ErrorKind),
}

/// What one transfer is set up with, beyond its operation's options.
struct Config<'a> {
    url: &'a [u8],
    /// The URL is taken for HTTP's: HTTP's options are set.
    http: bool,
    resume: Option<options::Resume>,
    upload: bool,
    /// What `--data` gives, unless `--get` put it in the query.
    post: Option<&'a [u8]>,
    /// The tree `--form` gives.
    form: Option<TryArc<curl_core::mime::Mime>>,
    /// The HTTP method the options chose for it.
    method: tool::Method,
    /// Standard output is a terminal, and the output goes there.
    terminal: bool,
    /// `--progress-bar`'s.
    bar: Option<&'a Bar>,
}

/// The `--cookie` strings as one (`cookie_setopts`): `;` between them,
/// and a blank unless the next starts with one.
fn joined_cookies(cookies: &[&[u8]], msgs: &Messages) -> Result<Option<Vec<u8>>, ErrorKind> {
    let Some((first, rest)) = cookies.split_first() else {
        return Ok(None);
    };
    let oom = |_| ErrorKind::OutOfMemory;
    let mut send = copy(first).map_err(oom)?;
    for cookie in rest {
        send.try_extend_from_slice(b";").map_err(oom)?;
        if !cookie.first().is_some_and(|&b| b == b' ' || b == b'\t') {
            send.try_extend_from_slice(b" ").map_err(oom)?;
        }
        send.try_extend_from_slice(cookie).map_err(oom)?;
    }
    // C builds it in a buffer of 8200 bytes, its zero byte counted.
    if send.len() >= MAX_REQUEST_COOKIE {
        msgs.warn(&[b"skipped provided cookie, the cookie header would go over 8200 bytes"]);
        return Err(ErrorKind::TooLarge);
    }
    Ok(Some(send))
}

/// Set up the transfer of `config.url` as `config2setopts` sets it.
fn configure(
    easy: &mut Easy,
    op: &Operation<'_>,
    run: &Shared<'_, '_>,
    out: &output::Output,
    config: &Config<'_>,
) -> Result<(), OutOfMemory> {
    let bar = config.bar;
    let o = easy.options_mut();
    o.set_url(Some(config.url))?;
    if let Some(protocol) = op.default_protocol {
        o.set_default_protocol(Some(protocol.name().as_bytes()))?;
    }
    if config.upload {
        o.method = Method::Upload;
    } else if let Some(post) = config.post {
        // `setopt_post`'s POSTFIELDS.
        let mut body = Vec::new();
        body.try_extend_from_slice(post)?;
        o.method = Method::Post;
        o.upload = options::UploadSource::Bytes(TryArc::try_new(body)?);
    } else if let Some(form) = &config.form {
        o.method = Method::Post;
        let tree = curl_core::mime::Fixed::new(form.clone());
        o.upload = options::UploadSource::Mime(Handler::mime(tree)?);
    } else if op.no_body {
        o.method = Method::Head;
    }
    if op.form_escape {
        o.mime.make_mut()?.form_escape = true;
    }
    o.resume = config.resume;
    o.range = op.range.as_deref().map(copy).transpose()?;
    o.progress = if run.global.no_progress || run.msgs.silent || config.terminal {
        Progress::Off
    } else if let Some(bar) = bar {
        Progress::Handler(bar.handler()?)
    } else {
        Progress::Meter
    };
    if let Some(tracer) = run.tracer {
        o.output.verbose = true;
        o.callbacks.debug = Some(tracer.handler(config.terminal)?);
    }
    o.callbacks.write = Some(out.body_handler()?);
    o.callbacks.header = Some(out.header_handler()?);
    // `credentials_and_headers_setopts`.
    let http = &mut o.http;
    // `--json` types the request and accepts JSON, unless the headers
    // say otherwise (`get_args`).
    let json = [
        (&b"Content-Type"[..], &b"Content-Type: application/json"[..]),
        (b"Accept", b"Accept: application/json"),
    ]
    .map(|(name, line)| (op.json && !in_list(&op.headers, name)).then_some(line));
    http.headers =
        options::UserHeaders::new(op.headers.iter().copied().chain(json.into_iter().flatten()))?;
    http.referer = op.referer.map(copy).transpose()?;
    http.custom_method = op.custom_request.map(copy).transpose()?;
    http.request_target = op.request_target.map(copy).transpose()?;
    // `customrequest_helper`.
    if let Some(custom) = op.custom_request {
        let implied = config.method.implied();
        if custom.eq_ignore_ascii_case(implied) {
            run.msgs.note(&[
                b"Unnecessary use of -X or --request, ",
                implied,
                b" is already inferred.",
            ]);
        } else if custom.eq_ignore_ascii_case(b"head") {
            run.msgs.warn(&[
                b"Setting custom HTTP method to HEAD with -X/--request may not work the way \
                  you want. Consider using -I/--head instead.",
            ]);
        }
    }
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
    // A user given without a password has had one asked for.
    if let Some(pair) = op.user.as_deref() {
        *o.login.make_mut()? = options::Login::from_pair(pair)?;
    }
    let netrc = if op.netrc_optional {
        options::NetrcMode::Optional
    } else if op.netrc || op.netrc_file.is_some() {
        options::NetrcMode::Required
    } else {
        options::NetrcMode::Ignored
    };
    if netrc != options::NetrcMode::Ignored {
        let o = o.netrc.make_mut()?;
        o.mode = netrc;
        o.file = op.netrc_file.map(copy).transpose()?;
    }
    if let Some(token) = op.bearer {
        o.login.make_mut()?.bearer = Some(copy(token)?);
    }
    if !op.auth.is_empty() {
        http.auth = options::HttpAuth(op.auth);
    }
    http.raw = op.raw;
    http.raw_content = op.raw;
    http.ignore_content_length = op.ignore_content_length;
    o.filetime = op.remote_time;
    o.time_condition = op.time_cond;
    // One method, in C's order (`proxy_setopts`).
    let proxy_auth = if op.proxy_anyauth {
        Some(options::AuthMethods::ANY)
    } else if op.proxy_digest {
        Some(options::AuthMethods::DIGEST)
    } else if op.proxy_basic {
        Some(options::AuthMethods::BASIC)
    } else {
        None
    };
    // The debug test build suppresses them on request as well, as C's
    // library does.
    let suppress_connect_headers = op.suppress_connect_headers
        || (cfg!(feature = "debug-hooks")
            && curl_os::env::is_set(b"CURL_DBG_SUPPRESS_CONNECT_HDS"));
    // The proxy options are made only where one is given.
    if op.proxy.is_some()
        || op.noproxy.is_some()
        || op.preproxy.is_some()
        || op.proxytunnel
        || op.haproxy_protocol
        || op.haproxy_clientip.is_some()
        || suppress_connect_headers
        || proxy_auth.is_some()
    {
        let p = o.proxy.make_mut()?;
        if let Some(proxy) = op.proxy {
            p.url = Some(copy(proxy)?);
            p.kind = op.proxy_kind;
        }
        p.no_proxy = op.noproxy.map(copy).transpose()?;
        p.pre_proxy = op.preproxy.map(copy).transpose()?;
        p.tunnel = op.proxytunnel;
        // As C's library takes them: an address turns the protocol on.
        p.haproxy = op.haproxy_protocol || op.haproxy_clientip.is_some();
        p.haproxy_client_ip = op.haproxy_clientip.map(copy).transpose()?;
        p.suppress_connect_headers = suppress_connect_headers;
        if let Some(methods) = proxy_auth {
            p.auth = options::HttpAuth(methods);
        }
    }
    o.url_rules.path_as_is = op.path_as_is;
    http.fail_on_error = op.fail == Fail::WithoutBody;
    o.limits.max_filesize = NonZeroU64::new(op.max_filesize);
    o.limits.max_recv_speed = NonZeroU64::new(op.limit_rate);
    o.limits.max_send_speed = NonZeroU64::new(op.limit_rate);
    // Reads of 100 KiB, or of a receive rate under that, so a limited
    // transfer reads no more than it may at once (`buffersize`).
    o.limits.buffer_size = options::BufferSize::clamped(match op.limit_rate {
        rate @ 1..TOOL_BUFFER => rate,
        _ => TOOL_BUFFER,
    });
    o.limits.total = TimeLimit::from_millis(op.timeout_ms);
    o.limits.connect = TimeLimit::from_millis(op.connect_timeout_ms);
    if let Some(ms) = op.happy_eyeballs_ms {
        o.limits.eyeballs = options::EyeballsDelay(Duration::from_millis(ms));
    }
    if !op.resolve.is_empty() {
        o.resolve.set(op.resolve.iter().copied())?;
    }
    o.connect_to.set(op.connect_to.iter().copied())?;
    o.ip_version = match op.ip_version {
        None => options::IpVersion::Any,
        Some(IpVersion::V4) => options::IpVersion::V4,
        Some(IpVersion::V6) => options::IpVersion::V6,
    };
    if config.http {
        http_options(o, op)?;
    }
    Ok(())
}

/// The options only a URL the tool takes for HTTP's is given
/// (`http_setopts`).
fn http_options(o: &mut options::Options, op: &Operation<'_>) -> Result<(), OutOfMemory> {
    let http = &mut o.http;
    // As `CURLOPT_AWS_SIGV4` takes it, after the methods: given, it is
    // the one method; not, it is none of them.
    http.signing
        .set(|g| &mut g.aws_sigv4, op.aws_sigv4.map(copy).transpose()?)?;
    http.auth.0 = match op.aws_sigv4 {
        Some(_) => options::AuthMethods::AWS_SIGV4,
        None => http.auth.0 & !options::AuthMethods::AWS_SIGV4,
    };
    http.follow = op.follow;
    http.unrestricted_auth = op.unrestricted_auth;
    http.auto_referer = op.auto_referer;
    if !op.proxy_headers.is_empty() {
        o.proxy.make_mut()?.headers = options::UserHeaders::new(op.proxy_headers.iter().copied())?;
    }
    // As `CURLOPT_MAXREDIRS` takes it: -1 no limit, at most 32767.
    http.max_redirects = options::MaxRedirects(match op.max_redirs.unwrap_or(50) {
        -1 => None,
        n => Some(u16::try_from(n.clamp(0, 0x7fff)).expect("clamped")),
    });
    if let Some(version) = op.http_version {
        http.version = match version {
            HttpVersion::Http10 => options::HttpVersion::Http10,
            HttpVersion::Http11 => options::HttpVersion::Http11,
        };
    }
    http.post_redirect = op.post_redirect;
    if op.compressed {
        http.accept_encoding = Some(curl_core::coding::AcceptEncoding::All);
    }
    http.transfer_encoding = op.tr_encoding;
    http.allow_09 = op.http09;
    if op.expect100_timeout_ms > 0 {
        // As `CURLOPT_EXPECT_100_TIMEOUT_MS` takes it, at most 65535.
        let ms = op.expect100_timeout_ms.min(0xffff);
        http.continue_wait = options::ContinueWait(Duration::from_millis(ms));
    }
    // `cookie_setopts`; the `--cookie` strings were joined already. The
    // cookie options are made only where one is given, as C's library
    // keeps none it is not given.
    if !op.cookie_files.is_empty() || op.cookie_jar.is_some() || op.cookie_session {
        let cookies = http.cookies.make_mut()?;
        for file in &op.cookie_files {
            cookies.files.push(file)?;
        }
        cookies.save_to = op.cookie_jar.map(copy).transpose()?;
        cookies.new_session = op.cookie_session;
    }
    Ok(())
}

/// `bytes`, owned.
/// What an HTTP message signature signs with, if any of it is given, as
/// `httpsig_setopts` sets it after the other HTTP options: the key and
/// its name required, the algorithm Ed25519 unless given, and the key
/// read from a file for `@` and its name. What is wrong is said here.
fn message_signature(
    o: &mut options::Options,
    given: Httpsig<'_>,
    msgs: &Messages,
) -> Result<(), ErrorKind> {
    use options::SignatureAlgorithm as A;
    if given == Httpsig::default() {
        return Ok(());
    }
    let oom = |_| ErrorKind::OutOfMemory;
    let Some(key) = given.key else {
        msgs.error(&[b"--httpsig-key is required"]);
        return Err(ErrorKind::FailedInit);
    };
    let Some(key_id) = given.key_id else {
        msgs.error(&[b"--httpsig-keyid is required"]);
        return Err(ErrorKind::FailedInit);
    };
    let algorithm = match given.algorithm {
        None => A::Ed25519,
        Some(name) if name.eq_ignore_ascii_case(b"ed25519") => A::Ed25519,
        Some(name) if name.eq_ignore_ascii_case(b"hmac-sha256") => A::HmacSha256,
        Some(name) => {
            msgs.error(&[b"--httpsig-algo: unsupported algorithm '", name, b"'"]);
            return Err(ErrorKind::FailedInit);
        }
    };
    o.http.auth.0 = options::AuthMethods::HTTPSIG;
    let components = given.components.map(copy).transpose().map_err(oom)?;
    let key_id = copy(key_id).map_err(oom)?;
    let key = match key.split_first() {
        Some((b'@', file)) => {
            // C opens `-` as a file of that name.
            let path: &[u8] = if file == b"-" { b"./-" } else { file };
            match crate::slurp::read(path, crate::slurp::As::Text) {
                Ok(hex) if hex.is_empty() => {
                    msgs.error(&[b"httpsig: key file '", file, b"' is empty"]);
                    return Err(ErrorKind::BadFunctionArgument);
                }
                Ok(hex) => hex,
                Err(crate::slurp::ReadFailed::Open) => {
                    msgs.error(&[b"httpsig: cannot open key file '", file, b"'"]);
                    return Err(ErrorKind::ReadError);
                }
                Err(crate::slurp::ReadFailed::Read) => {
                    msgs.error(&[b"httpsig: cannot read key file '", file, b"'"]);
                    return Err(ErrorKind::ReadError);
                }
                Err(crate::slurp::ReadFailed::OutOfMemory) => {
                    return Err(ErrorKind::OutOfMemory);
                }
            }
        }
        Some(_) => copy(key).map_err(oom)?,
        None => {
            msgs.error(&[b"httpsig: key is empty"]);
            return Err(ErrorKind::BadFunctionArgument);
        }
    };
    let signature = &mut o.http.signing.make_mut().map_err(oom)?.message;
    signature.algorithm = Some(algorithm);
    signature.components = components;
    signature.key_id = Some(key_id);
    signature.key = Some(key);
    Ok(())
}

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
    url: Given<'_>,
    easy: &Easy,
    out: &output::Output,
    bar: Option<&Bar>,
    ended: Ended,
) -> Result<(), ErrorKind> {
    let msgs = run.msgs;
    let (result, retries) = match ended {
        Ended::Ran(result) => (Some(settle(op, msgs, easy, out, result, false)), 0),
        Ended::Said(e) => (Some(settle(op, msgs, easy, out, Err(e), true)), 0),
        Ended::Settled(result, retries) => (Some(result), retries),
        Ended::Skipped => (None, 0),
    };
    // The output is closed once there is no retrying (`post_close_output`).
    let result = match result {
        Some(result) => {
            // The bar's line ends once the transfer does.
            if bar.is_some_and(Bar::shown) {
                // Nowhere to report a failed write, as in C.
                let _ = std::io::Write::write_all(&mut std::io::stderr(), b"\n");
            }
            let mut stream = out.stream();
            let mut result = result;
            let opened = stream.is_open_file();
            if stream.close().is_err() && result.is_ok() {
                let kind = ErrorKind::WriteError;
                // C's text, with its prefix twice.
                if let Ok(why) = try_format(format_args!(
                    "curl: ({}) Failed writing body",
                    exit_code(kind)
                )) {
                    msgs.error(&[why.as_bytes()]);
                }
                result = Err(kind);
            }
            // A file this transfer opened goes if it failed.
            if opened
                && result.is_err()
                && op.remove_on_error
                && let Some(name) = stream.file_name()
            {
                remove_partial(name, msgs);
            }
            if result.is_ok()
                && op.remote_time
                && let Some(name) = stream.file_name()
                && let Some(t) = easy.report().filetime()
            {
                set_file_time(name, t, msgs);
            }
            result
        }
        // A skipped transfer succeeds.
        None => Ok(()),
    };
    if let Some(format) = &op.write_out {
        let stream = out.stream();
        let facts = Facts {
            result,
            url: url.text,
            urlnum: url.num,
            num_headers: stream.num_headers(),
            num_retries: retries,
            filename: stream.file_name(),
            method: easy.effective_method(),
            report: easy.report(),
        };
        write_out::write(format.bytes(), &facts, run.stdout);
    }
    result
}

/// What one attempt's `result` comes to (`post_check_result`,
/// `post_output_handling`): its failure said, a failing response with
/// `--fail-with-body` made one, an output file that got nothing created,
/// and standard output flushed.
fn settle(
    op: &Operation<'_>,
    msgs: Messages,
    easy: &Easy,
    out: &output::Output,
    mut result: Result<(), ErrorKind>,
    said: bool,
) -> Result<(), ErrorKind> {
    // The transfer's reason, or the kind's, unless the tool said its own.
    if let Err(e) = result
        && !said
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
    // `--fail-with-body` fails an error response once its body is
    // written, unless a failure was reported already.
    let reported = result.is_err() && (!msgs.silent || msgs.show_error);
    if !reported
        && op.fail == Fail::WithBody
        && let Some(status) = easy.report().response_code().filter(|&s| s >= 400)
    {
        let kind = ErrorKind::HttpReturnedError;
        if let Ok(line) = try_format(format_args!(
            "curl: ({}) The requested URL returned error: {status}\n",
            exit_code(kind)
        )) {
            msgs.error_line(&[line.as_bytes()]);
        }
        result = Err(kind);
    }
    let mut stream = out.stream();
    // A successful transfer that wrote nothing still leaves its output
    // file, empty, unless a time condition kept the file from coming:
    // then the file is not even replaced.
    if result.is_ok() && !easy.report().condition_unmet() && !stream.create() {
        result = Err(ErrorKind::WriteError);
    }
    // Standard output is flushed here; a file, when it is closed.
    if stream.to_stdout() && stream.flush().is_err() && result.is_ok() {
        msgs.error(&[b"Failed writing body"]);
        result = Err(ErrorKind::WriteError);
    }
    result
}

/// Remove the output file `name` a failed transfer wrote
/// (`--remove-on-error`), if it is a regular file: said in a note, or
/// warned of if it is not removed.
fn remove_partial(name: &[u8], msgs: Messages) {
    if !fs::with_c_name(name, fs::stat).is_ok_and(|m| m.is_file()) {
        msgs.warn(&[b"Skipping removal; not a regular file: ", name]);
    } else if fs::with_c_name(name, fs::remove).is_ok() {
        msgs.note(&[b"Removed output file: ", name]);
    } else {
        msgs.warn(&[b"Failed removing: ", name]);
    }
}

/// Give `name` the modification and access time `t`, seconds after the
/// epoch (`setfiletime`). A failure is only warned about.
fn set_file_time(name: &[u8], t: i64, msgs: Messages) {
    if let Err(e) = fs::with_c_name(name, |c| fs::set_times(c, t)) {
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
    if curl_os::env::is_set(b"CURL_ISATTY") {
        return true;
    }
    std::io::stdout().is_terminal()
}

/// `url` with the name of `file`, the file it uploads, added to its path,
/// if the path ends without a name of its own and there is no query
/// (`add_file_name_to_url`): the name is what `file` has after its last
/// slash or backslash, URL-encoded.
fn with_file_name(url: &[u8], file: &[u8]) -> Result<Option<Vec<u8>>, ErrorKind> {
    let parse = ParseOptions {
        guess_scheme: true,
        non_support_scheme: true,
        ..ParseOptions::NONE
    };
    let mut url = Url::parse(url, parse).map_err(url_error)?;
    let path = url.get(Part::Path, GetOptions::NONE).map_err(url_error)?;
    match url.get(Part::Query, GetOptions::NONE) {
        Ok(_) => return Ok(None),
        Err(UrlErrorKind::OutOfMemory) => return Err(ErrorKind::OutOfMemory),
        Err(_) => {}
    }
    let slash = path.iter().rposition(|&b| b == b'/');
    if slash.is_some_and(|at| at + 1 < path.len()) {
        return Ok(None);
    }
    let after = file.iter().rposition(|&b| b == b'/').map_or(0, |at| at + 1);
    let name = match file[after..].iter().rposition(|&b| b == b'\\') {
        Some(at) => &file[after + at + 1..],
        None => &file[after..],
    };
    let oom = |OutOfMemory| ErrorKind::OutOfMemory;
    let name = curl_core::url::escape(name).map_err(oom)?;
    let mut new_path = Vec::new();
    new_path.try_extend_from_slice(&path).map_err(oom)?;
    if slash.is_none() {
        new_path.try_push(b'/').map_err(oom)?;
    }
    new_path.try_extend_from_slice(&name).map_err(oom)?;
    url.set(Part::Path, Some(&new_path), SetOptions::NONE)
        .map_err(url_error)?;
    let shown = GetOptions {
        default_scheme: true,
        no_guess_scheme: true,
        ..GetOptions::NONE
    };
    url.get(Part::Url, shown).map(Some).map_err(url_error)
}

/// The file name `--remote-name` saves `url` to: what its path has after
/// its last separator, trailing separators left out, or `curl_response`
/// if it has none (`get_url_file_name`).
fn url_file_name(url: &[u8], msgs: &Messages) -> Result<Vec<u8>, ErrorKind> {
    let parse = ParseOptions {
        guess_scheme: true,
        ..ParseOptions::NONE
    };
    let url = Url::parse(url, parse).map_err(url_error)?;
    let path = url.get(Part::Path, GetOptions::NONE).map_err(url_error)?;
    let separator = |b: &u8| matches!(b, b'/' | b'\\');
    let trailing = path.iter().rev().take_while(|b| separator(b)).count();
    let path = &path[..path.len() - trailing];
    // A backslash counts only after the last slash.
    let slash = path.iter().rposition(|&b| b == b'/');
    let tail = slash.map_or(path, |at| &path[at + 1..]);
    let name = match tail.iter().rposition(|&b| b == b'\\') {
        Some(at) => &tail[at + 1..],
        None if slash.is_some() => tail,
        None => {
            msgs.warn(&[b"No remote filename, uses \"curl_response\""]);
            b"curl_response"
        }
    };
    let mut copy = Vec::new();
    copy.try_extend_from_slice(name)
        .map_err(|OutOfMemory| ErrorKind::OutOfMemory)?;
    Ok(copy)
}

/// What the tool takes a URL's protocol for (`url_proto_and_rewrite`'s
/// token).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum UrlProto {
    /// HTTP or HTTPS.
    Http,
    /// IPFS or IPNS, which go to a gateway.
    Ipfs(crate::ipfs::Kind),
    /// Another, or none it knows.
    Other,
}

/// The protocol of `url`'s scheme, guessed from its host if it names
/// none, or `default`'s (`--proto-default`) then; a URL that does not
/// parse has none (`url_proto_and_rewrite`). An IPFS one comes with the
/// URL parsed, to be rewritten.
fn url_proto(
    url: &[u8],
    default: Option<Protocol>,
) -> Result<(UrlProto, Option<Url>), OutOfMemory> {
    let parse = ParseOptions {
        guess_scheme: true,
        non_support_scheme: true,
        ..ParseOptions::NONE
    };
    let oom = |e| match e {
        UrlErrorKind::OutOfMemory => Err(OutOfMemory),
        _ => Ok((UrlProto::Other, None)),
    };
    let url = match Url::parse(url, parse) {
        Ok(url) => url,
        Err(e) => return oom(e),
    };
    // With a default, a scheme only guessed counts as none.
    let get = GetOptions {
        no_guess_scheme: default.is_some(),
        default_scheme: default.is_none(),
        ..GetOptions::NONE
    };
    let scheme = match (url.get(Part::Scheme, get), default) {
        (Ok(scheme), _) => scheme,
        (Err(UrlErrorKind::NoScheme), Some(default)) => {
            let mut name = Vec::new();
            name.try_extend_from_slice(default.name().as_bytes())?;
            name
        }
        (Err(e), _) => return oom(e),
    };
    if let Some(kind) = crate::ipfs::Kind::of_scheme(&scheme) {
        return Ok((UrlProto::Ipfs(kind), Some(url)));
    }
    let http = [&b"http"[..], b"https"]
        .iter()
        .any(|name| scheme.eq_ignore_ascii_case(name));
    Ok((
        if http {
            UrlProto::Http
        } else {
            UrlProto::Other
        },
        None,
    ))
}

/// Why the query of `--get` or `--url-query` could not be added to a
/// URL.
#[derive(Debug, PartialEq, Eq)]
enum QueryFailed {
    /// The URL does not parse: the tool says so itself.
    Parse(ErrorKind),
    /// The query could not be set, or the URL read back.
    Set(ErrorKind),
}

/// `url` with `query` added to its query, after a `&` if it has one, the
/// scheme left out if it was only guessed (`append2query`).
fn with_query(url: &[u8], query: &[u8]) -> Result<Vec<u8>, QueryFailed> {
    let parse = ParseOptions {
        guess_scheme: true,
        ..ParseOptions::NONE
    };
    let mut url = Url::parse(url, parse).map_err(|e| QueryFailed::Parse(url_error(e)))?;
    let append = SetOptions {
        append_query: true,
        ..SetOptions::NONE
    };
    let shown = GetOptions {
        no_guess_scheme: true,
        ..GetOptions::NONE
    };
    url.set(Part::Query, Some(query), append)
        .and_then(|()| url.get(Part::Url, shown))
        .map_err(|e| QueryFailed::Set(url_error(e)))
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

/// The file to upload, opened, with its size if it is a regular file;
/// standard input for `-`, of a size not known, and started over only if
/// it is a file.
fn open_upload(name: &[u8]) -> Result<UploadSource, Unopened> {
    let (file, size) = if name == b"-" {
        (curl_os::fs::stdin().map_err(|_| Unopened::Io)?, None)
    } else {
        let file = fs::with_c_name(name, fs::open_read).map_err(|_| Unopened::Io)?;
        let meta = file.metadata().map_err(|_| Unopened::Io)?;
        #[cfg_attr(not(feature = "debug-hooks"), expect(unused_mut))]
        let mut size = meta.is_file().then_some(meta.len());
        // The debug test build takes the size from `CURL_UPLOAD_SIZE`,
        // as if the file had grown since (`pre_transfer`).
        #[cfg(feature = "debug-hooks")]
        if let Some(n) = curl_os::env::var_into(b"CURL_UPLOAD_SIZE", &mut [0u8; 32])
            .map(<std::ffi::OsStr as std::os::unix::ffi::OsStrExt>::from_bytes)
            .and_then(crate::memlimit)
        {
            size = Some(n);
        }
        (file, size)
    };
    let file = curl_alloc::TryArc::try_new(std::sync::Mutex::new(file))
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
struct UploadFile(curl_alloc::TryArc<std::sync::Mutex<File>>);

impl ReadHandler for UploadFile {
    fn read(&self, _: &mut TransferCx<'_>, buf: &mut [u8]) -> Read {
        // C takes a failed read for the end of the file; here it fails
        // the transfer rather than send part of the file as all of it
        // (DIVERGENCE.md).
        loop {
            match self.0.lock().expect("no panic holds it").read(buf) {
                Ok(n) => return NonZeroUsize::new(n).map_or(Read::Eof, Read::Data),
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
                Err(_) => return Read::Fail,
            }
        }
    }
}

impl Rewind for UploadFile {
    fn rewind(&self, cx: &mut TransferCx<'_>) -> Result<(), RewindFailed> {
        match self
            .0
            .lock()
            .expect("no panic holds it")
            .seek(SeekFrom::Start(0))
        {
            Ok(_) => Ok(()),
            Err(_) => {
                // C's seek callback answers `CURL_SEEKFUNC_CANTSEEK`, and
                // its library says so.
                cx.fail(b"seek callback returned error 2");
                Err(RewindFailed)
            }
        }
    }
}

/// Whether a header line names `name`, followed by a colon or a
/// semicolon (`inlist`).
fn in_list(headers: &[&[u8]], name: &[u8]) -> bool {
    headers.iter().any(|h| {
        h.len() > name.len()
            && h[..name.len()].eq_ignore_ascii_case(name)
            && matches!(h[name.len()], b':' | b';')
    })
}

/// The content codings this build undoes: those of the libraries it is
/// linked with, as C's.
fn decoders() -> curl_core::coding::Decoders {
    use curl_core::coding::{Coding, Decoders};
    Decoders::none()
        .with(Coding::Deflate, curl_zlib::deflate)
        .with(Coding::Gzip, curl_zlib::gzip)
        .with(Coding::Brotli, curl_brotli::decoder)
        .with(Coding::Zstd, curl_zstd::decoder)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `retrycheck`'s reasons: failures that may pass, the HTTP codes that
    /// say so (with `--fail`, as its failure too), and with
    /// `--retry-all-errors` any failure.
    #[test]
    fn retries_for_c_reasons() {
        let mut op = Operation::default();
        let http = Some(Protocol::Http);
        let timed_out = Err(ErrorKind::OperationTimedout);
        assert_eq!(reason(&op, timed_out, None, None), Some(Reason::Timeout));
        let resolve = Err(ErrorKind::CouldntResolveHost);
        assert_eq!(reason(&op, resolve, None, None), Some(Reason::Timeout));
        for code in [408, 429, 500, 502, 503, 504, 522, 524] {
            assert_eq!(reason(&op, Ok(()), http, Some(code)), Some(Reason::Http));
        }
        for code in [200, 404, 501, 505, 523] {
            assert_eq!(reason(&op, Ok(()), http, Some(code)), None, "{code}");
        }
        assert_eq!(reason(&op, Ok(()), None, Some(503)), None);
        let failed = Err(ErrorKind::HttpReturnedError);
        assert_eq!(reason(&op, failed, http, Some(503)), None);
        op.fail = Fail::WithoutBody;
        assert_eq!(reason(&op, failed, http, Some(503)), Some(Reason::Http));
        let refused = Err(ErrorKind::CouldntConnect);
        assert_eq!(reason(&op, refused, http, None), None);
        op.retry_all_errors = true;
        assert_eq!(reason(&op, refused, http, None), Some(Reason::AllErrors));
        assert_eq!(reason(&op, Ok(()), http, Some(404)), None);
    }

    /// No wait given: a second, then doubled, up to ten minutes.
    #[test]
    fn backs_off_as_c_does() {
        let waits: Vec<u64> = std::iter::successors(Some(0), |&w| Some(backoff(w)))
            .skip(1)
            .take(12)
            .collect();
        assert_eq!(
            waits,
            [
                1000, 2000, 4000, 8000, 16000, 32000, 64000, 128000, 256000, 512000, 600000, 600000
            ]
        );
    }

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
    /// the file's name, encoded; a query keeps the URL as it is.
    #[test]
    fn adds_a_file_name_to_a_bare_path() {
        let named = |url: &str, file: &str| {
            with_file_name(url.as_bytes(), file.as_bytes())
                .map(|u| u.map(|u| String::from_utf8(u).unwrap()))
        };
        let some = |s: &str| Ok(Some(s.to_string()));
        assert_eq!(named("file:///dir/", "a/b c"), some("file:///dir/b%20c"));
        assert_eq!(named("file:///dir/f", "a"), Ok(None));
        assert_eq!(named("file:///dir/?q", "a"), Ok(None));
        assert_eq!(named("http://host", "x\\y"), some("http://host/y"));
        // Without a scheme one is guessed, and not shown; one not supported
        // is still read.
        assert_eq!(named("host/dir/", "f"), some("host/dir/f"));
        assert_eq!(named("nosuch://host/f", "a"), Ok(None));
        assert_eq!(named("http://[bad/", "a"), Err(ErrorKind::UrlMalformat));
    }

    /// `url_proto_and_rewrite`'s token: the scheme's, guessed if the URL
    /// names none, `--proto-default`'s then, none if it does not parse.
    #[test]
    fn takes_a_url_s_protocol_as_c_does() {
        let proto = |url: &str, default| url_proto(url.as_bytes(), default).unwrap().0;
        let http = |url: &str, default| proto(url, default) == UrlProto::Http;
        assert!(http("http://h/", None));
        assert!(http("HTTPS://h/", None));
        assert!(http("h/p", None), "guessed");
        assert!(!http("ftp.h/p", None), "guessed FTP");
        assert!(http("ftp.h/p", Some(Protocol::Http)), "the default");
        assert!(!http("h/p", Some(Protocol::File)), "the default");
        assert!(http("http://h/", Some(Protocol::File)), "given");
        assert!(!http("file:///f", None));
        assert!(!http("ipfs://cid", None));
        let ipfs =
            |url: &str, default| proto(url, default) == UrlProto::Ipfs(crate::ipfs::Kind::Ipfs);
        assert!(ipfs("IPFS://cid", None));
        assert!(ipfs("ipfs://cid", Some(Protocol::Http)), "given");
        assert!(!ipfs("cid", None));
        assert!(!http("http://[bad/", None), "does not parse");
    }

    /// `append2query`: the query added after any there, as given, and a
    /// guessed scheme left out for `--proto-default` to choose (2008).
    #[test]
    fn adds_the_query_as_c_does() {
        let queried = |url: &str, query: &str| {
            with_query(url.as_bytes(), query.as_bytes()).map(|u| String::from_utf8(u).unwrap())
        };
        let ok = |s: &str| Ok(s.to_string());
        assert_eq!(queried("ftp.test", "hello"), ok("ftp.test/?hello"));
        assert_eq!(queried("http://h/p", "a=b&c=d"), ok("http://h/p?a=b&c=d"));
        // Not encoded: the library refuses the space later, as C's does.
        assert_eq!(queried("http://h/p?x#f", "a b"), ok("http://h/p?x&a b#f"));
        assert_eq!(
            queried("http://[bad/", "a"),
            Err(QueryFailed::Parse(ErrorKind::UrlMalformat))
        );
        assert_eq!(
            queried("nosuch://h/", "a"),
            Err(QueryFailed::Parse(ErrorKind::UnsupportedProtocol))
        );
    }

    /// `--remove-on-error` removes a file named long without allocating,
    /// as C does: std copied a name of 384 bytes or more with an
    /// allocation that cannot fail, which aborted a torture run.
    /// (tests/long_names.rs runs the others; no `file:` transfer fails
    /// after its output is opened.)
    #[cfg(feature = "debug-hooks")]
    #[test]
    fn removes_a_partial_file_named_long_without_allocating() {
        let dir = std::env::temp_dir().join(format!("curl-tool-remove-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("f"), b"partial").unwrap();
        let mut name = dir.as_os_str().as_encoded_bytes().to_vec();
        name.push(b'/');
        while name.len() < 400 {
            name.extend_from_slice(b"./");
        }
        name.push(b'f');
        let mut msgs = Messages::new();
        msgs.silent = true;
        let ((), n) = curl_alloc::track::count_allocations(|| remove_partial(&name, msgs));
        let removed = !dir.join("f").exists();
        std::fs::remove_dir_all(&dir).unwrap();
        assert!(removed);
        assert_eq!(n, 0, "removing the file allocated");
    }

    /// `show_dir_errno`'s texts.
    #[test]
    fn says_why_a_directory_was_not_made_as_c_does() {
        use std::io::ErrorKind as Io;
        let said = |kind| dir_error(kind, b"d/e").concat();
        for (kind, text) in [
            (
                Io::InvalidFilename,
                &b"The directory name d/e is too long"[..],
            ),
            (
                Io::ReadOnlyFilesystem,
                b"d/e resides on a read-only file system",
            ),
            (
                Io::StorageFull,
                b"No space left on the file system that would contain the directory d/e",
            ),
            (
                Io::QuotaExceeded,
                b"Cannot create directory d/e because you exceeded your quota",
            ),
            (Io::NotADirectory, b"Error creating directory d/e"),
        ] {
            assert_eq!(said(kind), text, "{kind:?}");
        }
    }

    /// `is_outfile_auto_resumable`: a GET resuming its output file, open,
    /// from where the attempt started, that wrote something, all of it.
    #[test]
    fn resumes_only_what_c_resumes() {
        // Removed however the test ends, so a failing run leaves nothing.
        struct Removed(std::path::PathBuf);
        impl Drop for Removed {
            fn drop(&mut self) {
                let _ = std::fs::remove_file(&self.0);
            }
        }
        let path = Removed(
            std::env::temp_dir().join(format!("curl-tool-resumable-{}", std::process::id())),
        );
        let path = &path.0;
        std::fs::write(path, b"held").unwrap();
        let out =
            output::Output::file(path.as_os_str().as_encoded_bytes(), Messages::new()).unwrap();
        assert!(out.stream().open_to_append());
        let mut op = Operation {
            resume: Some(Resume::FromOutput),
            ..Operation::default()
        };
        let retrying = Retrying {
            start: Instant::now(),
            retries: 0,
            wait_ms: 0,
            resumed_at: 4,
        };
        let get = || Attempt {
            result: Err(ErrorKind::PartialFile),
            upload: false,
            method: tool::Method::Unset,
        };
        let resumable =
            |op: &Operation<'_>, r: &Retrying, a: &Attempt| r.resumable(op, &out.stream(), a);
        // Nothing written yet.
        assert!(!resumable(&op, &retrying, &get()));
        assert_eq!(
            out.stream().body(b"more"),
            curl_core::handler::Write::Accepted
        );
        assert!(resumable(&op, &retrying, &get()));
        assert!(resumable(
            &op,
            &retrying,
            &Attempt {
                method: tool::Method::Get,
                ..get()
            }
        ));
        for (why, attempt) in [
            (
                "an upload",
                Attempt {
                    upload: true,
                    ..get()
                },
            ),
            (
                "a HEAD",
                Attempt {
                    method: tool::Method::Head,
                    ..get()
                },
            ),
            (
                "a write error",
                Attempt {
                    result: Err(ErrorKind::WriteError),
                    ..get()
                },
            ),
            (
                "a range error",
                Attempt {
                    result: Err(ErrorKind::RangeError),
                    ..get()
                },
            ),
        ] {
            assert!(!resumable(&op, &retrying, &attempt), "{why}");
        }
        let elsewhere = Retrying {
            resumed_at: 0,
            ..retrying
        };
        assert!(!resumable(&op, &elsewhere, &get()), "from elsewhere");
        op.custom_request = Some(b"GET");
        assert!(!resumable(&op, &retrying, &get()), "-X");
        op.custom_request = None;
        op.resume = Some(Resume::At(4));
        assert!(!resumable(&op, &retrying, &get()), "-C 4");
        op.resume = Some(Resume::FromOutput);
        // Standard output is no file to resume.
        let stdout = Stdout::new().unwrap();
        let to_stdout = output::Output::stdout(&stdout, Messages::new()).unwrap();
        assert_eq!(
            to_stdout.stream().body(b"x"),
            curl_core::handler::Write::Accepted
        );
        let from_0 = Retrying {
            resumed_at: 0,
            ..retrying
        };
        assert!(
            !from_0.resumable(&op, &to_stdout.stream(), &get()),
            "stdout"
        );
        drop(out);
    }

    /// `inlist`: the name, then a colon or a semicolon.
    #[test]
    fn finds_a_header_as_c_does() {
        let headers: [&[u8]; 3] = [b"Abcdef:x", b"content-type;", b"Accept"];
        assert!(in_list(&headers, b"Content-Type"));
        assert!(!in_list(&headers, b"Accept"));
        assert!(!in_list(&headers, b"Abcdef:"));
        assert!(!in_list(&[b"Accepts: x"], b"Accept"));
        assert!(!in_list(&[b"Abcdef:x"], b"Accept"));
        assert!(in_list(&[b"accept:"], b"Accept"));
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
