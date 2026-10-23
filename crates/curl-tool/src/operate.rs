//! Running what the command line asks for: each URL's transfer, one after
//! another (`src/tool_operate.c`, its serial path), or all at once
//! (`parallel`).

mod parallel;

use std::borrow::Cow;
use std::cell::{Cell, RefCell};
use std::fs::File;
use std::io::{IsTerminal as _, Read as _, Seek as _, SeekFrom, Write as _};
use std::num::{NonZeroU16, NonZeroU64, NonZeroUsize};
use std::ops::{Deref, DerefMut};
use std::os::fd::AsFd as _;
use std::time::{Duration, Instant};

use curl_alloc::{OutOfMemory, TryArc, TryVec as _, try_format};
use curl_core::cookie::Suffixes;
use curl_core::easy::Easy;
use curl_core::error::{ErrorKind, UrlErrorKind};
use curl_core::handler::{Handler, HeaderOrigin, Read, ReadHandler, Rewind, RewindFailed};
use curl_core::multi::TransferCx;
use curl_core::options::{self, Method, Progress, UploadSource};
use curl_core::report::{OsErrno, Request as HeaderRequest};
use curl_core::share::{Kind, Share};
use curl_core::time::TimeLimit;
use curl_core::url::{GetOptions, ParseOptions, Part, SetOptions, Url};
use curl_core::version::Protocol;
use curl_os::fs;

use crate::bar::Bar;
use crate::easysrc::{self, Setopt, Source};
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
    /// Its `--etag-save` file could not be opened: the rest of its
    /// operation is passed over.
    Abandoned,
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
    // In parallel the multi keeps the connections (`share_setup`).
    for kind in [Kind::Connections, Kind::Names, Kind::Cookies] {
        if kind != Kind::Connections || !line.global.parallel {
            share.keep(kind).expect("held by none yet");
        }
    }
    // And one list of public suffixes (`CURL_LOCK_DATA_PSL`).
    let suffixes = match curl_psl::suffixes() {
        Ok(suffixes) => suffixes,
        Err(OutOfMemory) => return Err(ErrorKind::OutOfMemory),
    };
    // The program `--libcurl` writes, made as the transfers are.
    let program = match line.global.libcurl.map(|_| Source::new()).transpose() {
        Ok(program) => program.map(RefCell::new),
        Err(OutOfMemory) => return Err(ErrorKind::OutOfMemory),
    };
    let run = Shared {
        libcurl: program.as_ref(),
        global: &line.global,
        stdout: &stdout,
        tracer: tracer.as_ref(),
        msgs,
        share: &share,
        suffixes: &suffixes,
        started: Cell::new(None),
    };
    let ending = if line.global.parallel {
        parallel::run_all(line, &run)
    } else {
        run_all(line, &run)
    };
    if let (Some(program), Some(name)) = (program, line.global.libcurl)
        && program.into_inner().finish(name, &stdout, &msgs).is_err()
    {
        return Err(ErrorKind::OutOfMemory);
    }
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
    let mut transfers = Transfers::new(&line.operations, run.msgs);
    // The result of the last transfer that ran.
    let mut last = Ok(());
    // Whether any transfer was made (`serial_transfers`'s `added`).
    let mut made = false;
    loop {
        match transfers.advance() {
            Ok(true) => {}
            Ok(false) if made => return last,
            Ok(false) => {
                run.msgs.error(&[b"no transfer performed"]);
                return Err(ErrorKind::ReadError);
            }
            Err(ending) => return ending,
        }
        rate_wait(run.global.ms_per_transfer, run.started.get(), run.msgs);
        let step = transfer(run, transfers.item());
        made |= !matches!(step, Step::Abandoned);
        match step {
            Step::Abandoned => transfers.abandon(),
            Step::Ran(result) => {
                last = result;
                if ends_run(result, run.global.fail_early) {
                    return result;
                }
            }
            Step::Failed(e) => return Err(e),
            Step::Unopened(e) => return last.and(Err(e)),
        }
    }
}

/// Which text is in use: one the command line gives, or the one a
/// pattern made last.
#[derive(Clone, Copy)]
enum Pick<'l> {
    Given(&'l [u8]),
    Held,
}

/// The transfers the command line asks for, made one at a time as C's
/// `create_transfer` makes them (its `struct State`): each operation's
/// nodes in turn, and for each node one transfer for each file its upload
/// pattern names, times each URL its URL pattern makes, the URL's changing
/// first (`create_single`). Each has the node's number.
struct Transfers<'a, 'l> {
    ops: &'a [Operation<'l>],
    msgs: Messages,
    /// What a name reads for a URL without patterns.
    literal: Glob,
    /// The operation walked, and its node, none before its first.
    op: usize,
    node: Option<usize>,
    /// Each URL's number on the command line, across operations
    /// (`outnum`).
    urlnum: u64,
    /// The transfer ready is its operation's first.
    first: bool,
    /// A transfer is ready.
    ready: bool,
    walk: Option<Walk<'l>>,
}

/// Where the walk of one node is.
struct Walk<'l> {
    given: Given<'l>,
    file: Option<&'l [u8]>,
    /// The upload pattern (`setup_input_file`).
    uploads: Option<Glob>,
    upload_once: bool,
    upload_held: Vec<u8>,
    upload: Option<Pick<'l>>,
    /// The URL pattern for the upload in use, once made for it
    /// (`setup_url_pattern`).
    urls: Option<Option<Glob>>,
    url_once: bool,
    url_held: Vec<u8>,
    url: Pick<'l>,
}

/// One transfer to make.
struct Item<'a, 'g, 'l> {
    op: &'a Operation<'l>,
    node: &'a Node<'l>,
    given: Given<'g>,
    upload: Option<&'g [u8]>,
    names: Option<Names<'g>>,
    /// The operation's first.
    first: bool,
}

impl<'a, 'l> Transfers<'a, 'l> {
    fn new(ops: &'a [Operation<'l>], msgs: Messages) -> Self {
        Transfers {
            ops,
            msgs,
            literal: Glob::literal(),
            op: 0,
            node: None,
            urlnum: 0,
            first: true,
            ready: false,
            walk: None,
        }
    }

    /// Make the next transfer ready: `false` once there is none, or how
    /// the run ends if it cannot be made.
    fn advance(&mut self) -> Result<bool, Ending> {
        let msgs = self.msgs;
        if std::mem::take(&mut self.ready) {
            self.first = false;
        }
        loop {
            let Some(op) = self.ops.get(self.op) else {
                return Ok(false);
            };
            if let Some(walk) = &mut self.walk {
                if let Some(urls) = &mut walk.urls {
                    match next_text(urls, &mut walk.url_once, &mut walk.url_held)? {
                        Some(true) => walk.url = Pick::Held,
                        Some(false) => walk.url = Pick::Given(walk.given.text),
                        None => {
                            walk.urls = None;
                            continue;
                        }
                    }
                    self.ready = true;
                    return Ok(true);
                }
                match next_text(
                    &mut walk.uploads,
                    &mut walk.upload_once,
                    &mut walk.upload_held,
                )? {
                    Some(true) => walk.upload = Some(Pick::Held),
                    Some(false) => walk.upload = walk.file.map(Pick::Given),
                    None => {
                        self.walk = None;
                        continue;
                    }
                }
                // Made again for each upload; a URL read from a file is
                // not globbed (`noglob`).
                let node = &op.nodes[self.node.expect("walking a node")];
                walk.urls = Some(expand(op, walk.given.text, node.literal, msgs)?);
                walk.url_once = true;
                continue;
            }
            if self.node.is_none() {
                if op.nodes.first().and_then(|n| n.url).is_none() {
                    msgs.help(&[b"(2) no URL specified"]);
                    return Err(Err(ErrorKind::FailedInit));
                }
                self.first = true;
            }
            let at = self.node.map_or(0, |n| n + 1);
            let next = op.nodes.get(at).map(|node| (node, node.url));
            let Some((node, Some(url))) = next else {
                if next.is_some() {
                    msgs.warn(&[b"Got more output options than URLs"]);
                }
                self.op += 1;
                self.node = None;
                continue;
            };
            self.node = Some(at);
            let given = Given {
                text: url,
                num: self.urlnum,
            };
            self.urlnum += 1;
            let file = match node.upload {
                Upload::File(file) => Some(file),
                Upload::Unset | Upload::Nothing => None,
            };
            let uploads = match file {
                Some(file) => expand(op, file, false, msgs)?,
                None => None,
            };
            self.walk = Some(Walk {
                given,
                file,
                uploads,
                upload_once: true,
                upload_held: Vec::new(),
                upload: None,
                urls: None,
                url_once: true,
                url_held: Vec::new(),
                url: Pick::Given(url),
            });
        }
    }

    /// Pass over what is left of the operation walked (C's
    /// `create_transfer` once `single_transfer` breaks its loop).
    fn abandon(&mut self) {
        self.op += 1;
        self.node = None;
        self.walk = None;
        self.ready = false;
    }

    /// The transfer `advance` made ready.
    fn item(&self) -> Item<'a, '_, 'l> {
        let op: &'a Operation<'l> = &self.ops[self.op];
        let node = &op.nodes[self.node.expect("an item is ready")];
        let walk = self.walk.as_ref().expect("an item is ready");
        let text = match walk.url {
            Pick::Given(text) => text,
            Pick::Held => &walk.url_held[..],
        };
        let upload = walk.upload.map(|pick| match pick {
            Pick::Given(file) => file,
            Pick::Held => &walk.upload_held[..],
        });
        let urls = walk.urls.as_ref().expect("an item is ready");
        // Names read the patterns while one is in use (`glob_inuse`).
        let names = (!op.globoff && (!node.literal || walk.file.is_some())).then(|| Names {
            url: urls.as_ref().unwrap_or(&self.literal),
            upload: walk.uploads.as_ref(),
        });
        Item {
            op,
            node,
            given: Given {
                text,
                num: walk.given.num,
            },
            upload,
            names,
            first: self.first,
        }
    }
}

/// `text`'s pattern, unless globbing is off, the text is `literal` or
/// it has none; a bad one said.
fn expand(
    op: &Operation<'_>,
    text: &[u8],
    literal: bool,
    msgs: Messages,
) -> Result<Option<Glob>, Ending> {
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
}

/// The next text of `glob` into `held` (`Some(true)`), or without a
/// pattern the text given, once (`Some(false)`); `None` when done.
fn next_text(
    glob: &mut Option<Glob>,
    once: &mut bool,
    held: &mut Vec<u8>,
) -> Result<Option<bool>, Ending> {
    match glob {
        Some(glob) => match glob.next_url() {
            Ok(Some(next)) => {
                *held = next;
                Ok(Some(true))
            }
            Ok(None) => Ok(None),
            Err(OutOfMemory) => Err(Err(ErrorKind::OutOfMemory)),
        },
        None => Ok(std::mem::take(once).then_some(false)),
    }
}

/// Whether a transfer that ended with `result` ends the run: a fatal
/// error, or any with `--fail-early` (`serial_transfers`).
fn ends_run(result: Result<(), ErrorKind>, fail_early: bool) -> bool {
    result.is_err_and(fatal) || (result.is_err() && fail_early)
}

/// Wait for what is left of `every` milliseconds, `--rate`'s, since the
/// last transfer `started`, if one did, saying so (`serial_transfers`).
fn rate_wait(every: u64, started: Option<Instant>, msgs: Messages) {
    let Some(started) = started else {
        return;
    };
    let took = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
    if let Some(wait) = rate_left(every, took) {
        if let Ok(note) = try_format(format_args!(
            "Transfer took {took} ms, waits {wait}ms as set by --rate"
        )) {
            msgs.note(&[note.as_bytes()]);
        }
        std::thread::sleep(Duration::from_millis(wait));
    }
}

/// How many milliseconds are left to wait of `every` between transfer
/// starts, `took` having passed since the last; none for no `--rate`.
fn rate_left(every: u64, took: u64) -> Option<u64> {
    (every != 0 && took < every).then(|| every - took)
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

/// The `If-None-Match:` header for the ETag in file `name`, its bytes
/// without line ends and zero bytes, or `""` for a file that does not
/// open, cannot be read or is empty (`etag_compare`). One that does not
/// open is said. A file of line ends alone gives the header no value,
/// which is not sent: C's `file2string` has a string for it, empty.
fn etag_header(name: &[u8], msgs: &Messages) -> Result<Vec<u8>, OutOfMemory> {
    let read = match fs::with_c_name(name, fs::open_read) {
        Ok(mut file) => crate::slurp::read_from(&mut file, crate::slurp::As::Binary).ok(),
        Err(e) => {
            let why = crate::os_message(&e);
            msgs.warn(&[b"Failed to open ", name, b": ", why.as_bytes()]);
            None
        }
    };
    let mut header = Vec::new();
    header.try_extend_from_slice(b"If-None-Match: ")?;
    match read.filter(|bytes| !bytes.is_empty()) {
        Some(bytes) => bytes
            .split(|&b| matches!(b, b'\r' | b'\n' | 0))
            .try_for_each(|part| header.try_extend_from_slice(part))?,
        None => header.try_extend_from_slice(b"\"\"")?,
    }
    Ok(header)
}

/// Errors after which nothing more is tried (`is_fatal_error`). C's also
/// has `CURLE_UNKNOWN_OPTION`, which only libcurl's C API returns.
fn fatal(e: ErrorKind) -> bool {
    matches!(
        e,
        ErrorKind::FailedInit | ErrorKind::OutOfMemory | ErrorKind::BadFunctionArgument
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
    /// The program `--libcurl` writes, if asked for.
    libcurl: Option<&'a RefCell<Source>>,
    global: &'a Global<'l>,
    stdout: &'a Stdout,
    tracer: Option<&'a Tracer>,
    msgs: Messages,
    share: &'a Share,
    suffixes: &'a Suffixes,
    /// When the last transfer, or its last attempt, started, for
    /// `--rate`.
    started: Cell<Option<Instant>>,
}

/// Set up, run and finish one URL's transfer (`create_single`,
/// `pre_transfer`, the perform and `post_per_transfer`).
fn transfer(run: &Shared<'_, '_>, item: Item<'_, '_, '_>) -> Step {
    match create(run, item) {
        Made::Ready(per, easy) => per.run_serial(run, easy),
        Made::Unfinished(per, easy, ended) => {
            Step::Failed(per.end(run, &easy, ended).expect_err("a failure stays one"))
        }
        Made::Failed(e) => Step::Failed(e),
        Made::Abandoned => Step::Abandoned,
    }
}

/// A transfer made from the command line, set up and not yet ended (C's
/// `per_transfer`).
struct PerTransfer<'a, 'l> {
    op: &'a Operation<'l>,
    /// Its URL as set, and its number on the command line.
    url: Vec<u8>,
    num: u64,
    out: output::Output,
    bar: Option<Bar>,
    /// The file it uploads, opened for each attempt.
    upload: Option<Vec<u8>>,
    method: tool::Method,
    /// Its output file exists (`--skip-existing`): it does not run.
    skip: bool,
    /// Its output goes to a terminal: no meter is drawn for it.
    terminal: bool,
    retrying: Retrying,
}

/// What came of making a transfer.
enum Made<'a, 'l> {
    Ready(PerTransfer<'a, 'l>, Handle),
    /// It failed once its handle existed, and ends so.
    Unfinished(PerTransfer<'a, 'l>, Handle, Ended),
    /// It failed before: there is nothing to end (C's failed
    /// `create_transfer`).
    Failed(ErrorKind),
    /// Its `--etag-save` file could not be opened, and that was said.
    Abandoned,
}

/// Why an attempt could not start (`pre_transfer`).
enum Pre {
    Failed(ErrorKind),
    /// The file to upload could not be opened.
    Unopened,
}

/// A transfer that failed as it was made, to end as `ended` says, with
/// `given` for its URL.
fn unfinished<'a, 'l>(
    op: &'a Operation<'l>,
    out: &output::Output,
    method: tool::Method,
    easy: Handle,
    given: Given<'_>,
    ended: Ended,
) -> Made<'a, 'l> {
    match copy(given.text) {
        Ok(url) => Made::Unfinished(
            PerTransfer {
                op,
                url,
                num: given.num,
                out: out.clone(),
                bar: None,
                upload: None,
                method,
                skip: false,
                terminal: false,
                retrying: Retrying::new(op, None),
            },
            easy,
            ended,
        ),
        Err(OutOfMemory) => Made::Failed(ErrorKind::OutOfMemory),
    }
}

impl PerTransfer<'_, '_> {
    /// What is done once it is over, whatever its result
    /// (`post_per_transfer`); the result as it ends up.
    fn end(&self, run: &Shared<'_, '_>, easy: &Easy, ended: Ended) -> Result<(), ErrorKind> {
        let given = Given {
            text: &self.url,
            num: self.num,
        };
        let bar = self.bar.as_ref();
        finish(self.op, run, given, easy, &self.out, bar, ended)
    }

    /// Open what it uploads, for an attempt (`pre_transfer`).
    fn pre_transfer(&self, run: &Shared<'_, '_>, easy: &mut Easy) -> Result<(), Pre> {
        let Some(file) = self.upload.as_deref() else {
            return Ok(());
        };
        match open_upload(file) {
            Ok(source) => upload_setopts(easy, run, source).map_err(Pre::Failed),
            Err(Unopened::OutOfMemory) => Err(Pre::Failed(ErrorKind::OutOfMemory)),
            Err(Unopened::Io) => {
                run.msgs.help(&[b"cannot open '", file, b"'"]);
                Err(Pre::Unopened)
            }
        }
    }

    /// Run it to its end, attempt after attempt (the perform and
    /// `post_per_transfer` of `serial_transfers`).
    fn run_serial(mut self, run: &Shared<'_, '_>, mut easy: Handle) -> Step {
        let msgs = run.msgs;
        let ended = if self.skip {
            run.started.set(Some(Instant::now()));
            Ended::Skipped(Ok(()))
        } else {
            loop {
                run.started.set(Some(Instant::now()));
                // Opened for each attempt, from its start.
                match self.pre_transfer(run, &mut easy) {
                    Ok(()) => {}
                    Err(Pre::Failed(e)) => return self.fail(run, &easy, e),
                    Err(Pre::Unopened) => {
                        let ended = Ended::Ran(Err(ErrorKind::ReadError));
                        let result = self.end(run, &easy, ended);
                        return Step::Unopened(result.expect_err("a failure stays one"));
                    }
                }
                if let Some(source) = run.libcurl
                    && source.borrow_mut().perform().is_err()
                {
                    return self.fail(run, &easy, ErrorKind::OutOfMemory);
                }
                // The debug build runs a copy, which needs the share set
                // again, and lets the original go as `curl_easy_cleanup`
                // does.
                #[cfg(feature = "debug-hooks")]
                if run.global.test_duphandle {
                    let Ok(dup) = easy.try_clone() else {
                        return self.fail(run, &easy, ErrorKind::OutOfMemory);
                    };
                    drop(Handle(std::mem::replace(&mut *easy, dup)));
                    easy.set_share(Some(run.share.clone()));
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
                let result = settle(self.op, run, &self.url, &easy, &self.out, result, Told::Not);
                let attempt = Attempt {
                    result,
                    upload: self.upload.is_some(),
                    method: self.method,
                };
                match self
                    .retrying
                    .check(self.op, msgs, &mut easy, &self.out, attempt)
                {
                    Again::After(wait) => std::thread::sleep(wait),
                    Again::No(result) => break Ended::Settled(result, self.retrying.retries),
                }
            }
        };
        Step::Ran(self.end(run, &easy, ended))
    }

    /// It failed to start for a reason of the tool's.
    fn fail(mut self, run: &Shared<'_, '_>, easy: &Easy, e: ErrorKind) -> Step {
        self.bar = None;
        let result = self.end(run, easy, Ended::Ran(Err(e)));
        Step::Failed(result.expect_err("a failure stays one"))
    }
}

/// Set up one URL's transfer (`create_single`).
fn create<'a, 'l>(run: &Shared<'_, '_>, item: Item<'a, '_, 'l>) -> Made<'a, 'l> {
    let Item {
        op,
        node,
        given,
        upload,
        names,
        first,
    } = item;
    let msgs = run.msgs;
    let url = given.text;
    // The ETag to compare and where to save the new one
    // (`setup_etag_files`), before anything else.
    let etag = match op.etag_compare.map(|name| etag_header(name, &msgs)) {
        Some(Ok(header)) => Some(header),
        Some(Err(OutOfMemory)) => {
            msgs.error(&[b"Failed to allocate memory for custom etag header"]);
            return Made::Failed(ErrorKind::OutOfMemory);
        }
        None => None,
    };
    let etag_save = match op.etag_save {
        Some(name) => {
            if op.create_dirs
                && let Err(e) = create_dirs(name, &msgs)
            {
                return Made::Failed(e);
            }
            match output::EtagSave::open(name, run.stdout, &msgs) {
                Some(save) => Some(save),
                None => return Made::Abandoned,
            }
        }
        None => None,
    };
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
        return Made::Failed(ErrorKind::FailedInit);
    }
    // `--url-query` gives the query otherwise.
    let query = fields.or(op.url_query.as_deref());
    if upload.is_some() && method.choose(tool::Method::Put, &msgs).is_err() {
        return Made::Failed(ErrorKind::FailedInit);
    }
    // `check_post_resume`: data is not resumed, and C says so itself.
    let resumed = match op.resume {
        Some(Resume::FromOutput) => true,
        Some(Resume::At(n)) => n > 0,
        None => false,
    };
    if matches!(method, tool::Method::Post | tool::Method::Mime) && resumed {
        msgs.error(&[b"(43) HTTP upload cannot be resumed"]);
        return Made::Failed(ErrorKind::BadFunctionArgument);
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
                    return Made::Failed(e.kind);
                }
            };
            if globbed.is_empty() {
                msgs.warn(&[b"output glob produces empty string"]);
                return Made::Failed(ErrorKind::WriteError);
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
                    return Made::Failed(e);
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
                Err(OutOfMemory) => return Made::Failed(ErrorKind::OutOfMemory),
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
        return Made::Failed(ErrorKind::OutOfMemory);
    };
    let mut easy = Handle(Easy::new());
    easy.set_share(Some(run.share.clone()));
    easy.set_public_suffixes(Some(run.suffixes.clone()));
    easy.set_libraries(&LIBRARIES);
    easy.set_components(run.global.components.clone());
    // From here the transfer exists: a failure to set it up is its
    // result, and is finished as one (`run_all_transfers`'s cleanup).
    let orig = given;
    let failed = |easy, e| unfinished(op, &out, method, easy, orig, Ended::Ran(Err(e)));
    // A failure the tool has said already (C's `synthetic_error`).
    let said = |easy, e| unfinished(op, &out, method, easy, orig, Ended::Said(e));
    // `setup_headerfile`.
    if let Some(name) = op.dump_header {
        if op.create_dirs
            && name != b"-"
            && name != b"%"
            && let Err(e) = create_dirs(name, &msgs)
        {
            return failed(easy, e);
        }
        match out.dump_to(name, first, run.stdout) {
            Ok(()) => {}
            Err(output::DumpFailed::OutOfMemory) => return failed(easy, ErrorKind::OutOfMemory),
            Err(output::DumpFailed::Open) => return failed(easy, ErrorKind::WriteError),
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
            return failed(easy, e);
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
            return failed(easy, ErrorKind::WriteError);
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
            Err(e) => return failed(easy, e),
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
            return said(easy, e);
        }
        Some(Err(QueryFailed::Set(e))) => return failed(easy, e),
        None => given,
    };
    let url = given.text;
    // Only a URL taken for HTTP's is given HTTP's options; one for IPFS
    // goes to its gateway, or nowhere, said once (`synthetic_error`).
    let (proto, parsed) = match url_proto(url, op.default_protocol.map(|d| d.protocol)) {
        Ok(found) => found,
        Err(OutOfMemory) => return failed(easy, ErrorKind::OutOfMemory),
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
                    return unfinished(op, &out, method, easy, given, Ended::Said(e));
                }
            }
        }
        _ => given,
    };
    let url = given.text;
    {
        let mut stream = out.stream();
        stream.show_headers = op.show_headers;
        stream.terminal = terminal;
        stream.styled = run.global.styles(terminal);
        stream.binary_ok = node.output == Output::File(b"-");
        stream.no_buffer = op.no_buffer;
        stream.clobber = op.clobber;
        stream.etag_save = etag_save;
        // `--remote-header-name` names only a file `--remote-name` names
        // (`setup_header_cb`).
        if op.remote_header_name && output_is_remote {
            match output::FromHeader::new(op.output_dir) {
                Ok(from) => stream.name_from_header = Some(from),
                Err(OutOfMemory) => {
                    drop(stream);
                    return failed(easy, ErrorKind::OutOfMemory);
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
            Err(OutOfMemory) => return failed(easy, ErrorKind::OutOfMemory),
        }
    } else {
        None
    };
    // The tree `--form` gives, made for this transfer (`setopt_post`).
    let form = match (&op.form, method) {
        (Some(form), tool::Method::Mime) => match form.mime(&msgs) {
            Ok(mime) => match curl_alloc::TryArc::try_new(mime) {
                Ok(mime) => Some(mime),
                Err(OutOfMemory) => return failed(easy, ErrorKind::OutOfMemory),
            },
            Err(e) => return failed(easy, e),
        },
        _ => None,
    };
    let config = Config {
        url,
        proto,
        etag: etag.as_deref(),
        resume,
        upload: upload.is_some(),
        post,
        form,
        method,
        terminal,
        bar: bar.as_ref(),
    };
    let set = {
        let mut source = run.libcurl.map(RefCell::borrow_mut);
        let mut set = Setopt::new(&mut easy, source.as_deref_mut());
        setopts(&mut set, op, run, &out, &config)
    };
    if let Err(e) = set {
        return failed(easy, e);
    }
    let url = match copy(given.text) {
        Ok(url) => url,
        Err(OutOfMemory) => return failed(easy, ErrorKind::OutOfMemory),
    };
    let upload = match upload.map(copy).transpose() {
        Ok(upload) => upload,
        Err(OutOfMemory) => return failed(easy, ErrorKind::OutOfMemory),
    };
    let per = PerTransfer {
        op,
        url,
        num: given.num,
        out,
        bar,
        upload,
        method,
        skip,
        terminal,
        retrying: Retrying::new(op, resume_from),
    };
    Made::Ready(per, easy)
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
    ConnRefused,
    Http,
}

impl Reason {
    fn text(self) -> &'static [u8] {
        match self {
            Reason::AllErrors => b"(retrying all errors)",
            Reason::Timeout => b": timeout",
            Reason::ConnRefused => b": connection refused",
            Reason::Http => b": HTTP error",
        }
    }
}

/// Why an attempt that ended with `result`, its last response `code` over
/// `protocol`, would be tried again, if it would (`retrycheck`): a failure
/// that may pass, a connection refused (the last socket error, `os_errno`,
/// says why connecting failed) with `--retry-connrefused`, an HTTP response saying
/// so, or with `--retry-all-errors` any failure. An FTP 4xx (`RETRY_FTP`)
/// joins with FTP.
fn reason(
    op: &Operation<'_>,
    result: Result<(), ErrorKind>,
    protocol: Option<Protocol>,
    code: Option<u16>,
    os_errno: Option<OsErrno>,
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
    } else if op.retry_connrefused && result == Err(ErrorKind::CouldntConnect) {
        (os_errno.map(OsErrno::kind) == Some(std::io::ErrorKind::ConnectionRefused))
            .then_some(Reason::ConnRefused)
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
        let Some(reason) = reason(
            op,
            result,
            report.protocol(),
            report.response_code(),
            report.os_errno(),
        ) else {
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
            let resume = NonZeroU64::new(at).map(options::Resume::At);
            Setopt::new(easy, None)
                .unwritten("`retrycheck` sets it itself", |o| {
                    o.resume = resume;
                    Ok(())
                })
                .expect("setting a resume point cannot fail");
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
    /// Never started: its output file exists (`--skip-existing`). Only
    /// its `--write-out` is written, with the result given: success, or
    /// the run's when it ends parallel transfers.
    Skipped(Result<(), ErrorKind>),
    /// Not set up, for a reason the tool has said itself: it is not said
    /// again (C's `synthetic_error`).
    Said(ErrorKind),
}

/// What one transfer is set up with, beyond its operation's options.
struct Config<'a> {
    url: &'a [u8],
    /// The `If-None-Match:` header `--etag-compare` makes, after the
    /// others.
    etag: Option<&'a [u8]>,
    /// What the URL is taken for: HTTP's options are set for HTTP's.
    proto: UrlProto,
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

fn oom(_: OutOfMemory) -> ErrorKind {
    ErrorKind::OutOfMemory
}

/// What an option C's tool sets does here: nothing, as the library has
/// no such option, or the tool's own callbacks stand in for C's.
fn nothing(_: &mut options::Options) -> Result<(), ErrorKind> {
    Ok(())
}

/// `n` as the `long` C's tool passes.
fn long(n: u64) -> i64 {
    i64::try_from(n).unwrap_or(i64::MAX)
}

/// Set up the transfer of `config.url` as `config2setopts` sets it, in
/// its order: each option through `s`, which writes the call for
/// `--libcurl`.
fn setopts(
    s: &mut Setopt<'_>,
    op: &Operation<'_>,
    run: &Shared<'_, '_>,
    out: &output::Output,
    config: &Config<'_>,
) -> Result<(), ErrorKind> {
    use easysrc::Pointer::{Function, Object};
    // `gen_trace_setopts`.
    if let Some(tracer) = run.tracer {
        s.ptr("CURLOPT_DEBUGFUNCTION", Function, |o| {
            o.callbacks.debug = Some(tracer.handler(config.terminal).map_err(oom)?);
            Ok(())
        })?;
        s.ptr("CURLOPT_DEBUGDATA", Object, nothing)?;
        s.long("CURLOPT_VERBOSE", 1, |o| {
            o.output.verbose = true;
            Ok(())
        })?;
    }
    // `buffersize`.
    let size = buffer_size(op.limit_rate);
    s.long("CURLOPT_BUFFERSIZE", long(size), |o| {
        o.limits.buffer_size = options::BufferSize::clamped(size);
        Ok(())
    })?;
    s.str("CURLOPT_URL", Some(config.url), |o| {
        o.set_url(Some(config.url)).map_err(oom)
    })?;
    // Output to a terminal has no meter (`single_transfer`).
    let quiet = run.global.no_progress || run.msgs.silent || config.terminal;
    s.long("CURLOPT_NOPROGRESS", i64::from(quiet), |o| {
        o.progress = if quiet {
            Progress::Off
        } else {
            Progress::Meter
        };
        Ok(())
    })?;
    // `gen_cb_setopts`.
    s.ptr("CURLOPT_WRITEDATA", Object, nothing)?;
    s.ptr("CURLOPT_INTERLEAVEDATA", Object, nothing)?;
    s.ptr("CURLOPT_WRITEFUNCTION", Function, |o| {
        o.callbacks.write = Some(out.body_handler().map_err(oom)?);
        Ok(())
    })?;
    // What is uploaded is opened for each attempt (`pre_transfer`).
    s.ptr("CURLOPT_READDATA", Object, nothing)?;
    s.ptr("CURLOPT_READFUNCTION", Function, nothing)?;
    s.ptr("CURLOPT_SEEKDATA", Object, nothing)?;
    s.ptr("CURLOPT_SEEKFUNCTION", Function, nothing)?;
    if let Some(bar) = config.bar.filter(|_| !quiet) {
        s.ptr("CURLOPT_XFERINFOFUNCTION", Function, |o| {
            o.progress = Progress::Handler(bar.handler().map_err(oom)?);
            Ok(())
        })?;
        s.ptr("CURLOPT_XFERINFODATA", Object, nothing)?;
    }
    s.ptr("CURLOPT_HEADERFUNCTION", Function, |o| {
        o.callbacks.header = Some(out.header_handler().map_err(oom)?);
        Ok(())
    })?;
    s.ptr("CURLOPT_HEADERDATA", Object, nothing)?;
    proxy_setopts(s, op)?;
    credentials_and_headers(s, op, config.etag)?;
    transfer_setopts(s, op, run, config)?;
    if let UrlProto::Http { tls } = config.proto {
        http_setopts(s, op, tls, &run.msgs)?;
    }
    // `dns_and_network_setopts`.
    s.long(
        "CURLOPT_CONNECTTIMEOUT_MS",
        long(op.connect_timeout_ms),
        |o| {
            o.limits.connect = TimeLimit::from_millis(op.connect_timeout_ms);
            Ok(())
        },
    )?;
    s.offt("CURLOPT_MAXFILESIZE_LARGE", long(op.max_filesize), |o| {
        o.flow
            .set(|g| &mut g.max_filesize, NonZeroU64::new(op.max_filesize))
            .map_err(oom)?;
        Ok(())
    })?;
    let (ip_version, resolve) = match op.ip_version {
        None => (options::IpVersion::Any, 0),
        Some(IpVersion::V4) => (options::IpVersion::V4, 1),
        Some(IpVersion::V6) => (options::IpVersion::V6, 2),
    };
    s.long("CURLOPT_IPRESOLVE", resolve, |o| {
        o.ip_version = ip_version;
        Ok(())
    })?;
    // Set only if one is asked for, as C's mask is set only if not 0.
    if op.socks5_basic || op.socks5_gssapi {
        let auth = options::Socks5Auth {
            basic: op.socks5_basic,
            gssapi: op.socks5_gssapi,
            only: false,
        };
        let mask = easysrc::socks5_mask(auth);
        s.bitmask("CURLOPT_SOCKS5_AUTH", easysrc::AUTH, mask, |o| {
            o.proxy.make_mut().map_err(oom)?.socks5_auth = auth;
            Ok(())
        })?;
    }
    s.long(
        "CURLOPT_IGNORE_CONTENT_LENGTH",
        i64::from(op.ignore_content_length),
        |o| {
            o.http.ignore_content_length = op.ignore_content_length;
            Ok(())
        },
    )?;
    if op.raw {
        s.long("CURLOPT_HTTP_CONTENT_DECODING", 0, |o| {
            o.http.raw_content = true;
            Ok(())
        })?;
        s.long("CURLOPT_HTTP_TRANSFER_DECODING", 0, |o| {
            o.http.raw = true;
            Ok(())
        })?;
    }
    // `tcp_setopts`.
    if op.nagle {
        s.long("CURLOPT_TCP_NODELAY", 0, |o| {
            o.sockets.make_mut().map_err(oom)?.nodelay = false;
            Ok(())
        })?;
    }
    if op.tcp_fastopen {
        s.long("CURLOPT_TCP_FASTOPEN", 1, |o| {
            o.sockets.make_mut().map_err(oom)?.fastopen = true;
            Ok(())
        })?;
    }
    if op.mptcp {
        s.ptr("CURLOPT_OPENSOCKETFUNCTION", Function, |o| {
            let opener = Handler::socket_opener(crate::sockopt::Mptcp).map_err(oom)?;
            o.sockets.make_mut().map_err(oom)?.open = Some(opener);
            Ok(())
        })?;
    }
    if op.no_keepalive {
        s.long("CURLOPT_TCP_KEEPALIVE", 0, nothing)?;
    } else {
        s.long("CURLOPT_TCP_KEEPALIVE", 1, |o| {
            o.sockets.make_mut().map_err(oom)?.keepalive.on = true;
            Ok(())
        })?;
        let time = op.keepalive_time;
        if time != 0 {
            let secs = Duration::from_secs(time);
            s.long("CURLOPT_TCP_KEEPIDLE", long(time), |o| {
                o.sockets.make_mut().map_err(oom)?.keepalive.idle = secs;
                Ok(())
            })?;
            s.long("CURLOPT_TCP_KEEPINTVL", long(time), |o| {
                o.sockets.make_mut().map_err(oom)?.keepalive.interval = secs;
                Ok(())
            })?;
        }
        let count = op.keepalive_cnt;
        if count != 0 {
            s.long("CURLOPT_TCP_KEEPCNT", long(count), |o| {
                let count = u32::try_from(count).unwrap_or(u32::MAX);
                o.sockets.make_mut().map_err(oom)?.keepalive.count = count;
                Ok(())
            })?;
        }
    }
    // `mail_and_sasl_setopts`.
    if op.create_file_mode != 0 {
        s.long(
            "CURLOPT_NEW_FILE_PERMS",
            i64::from(op.create_file_mode),
            |o| {
                o.new_file_mode =
                    options::FileMode::new(op.create_file_mode).expect("read as at most 0o777");
                Ok(())
            },
        )?;
    }
    // `misc_setopts`.
    s.ptr("CURLOPT_STDERR", Object, nothing)?;
    if !op.resolve.is_empty() {
        s.slist("CURLOPT_RESOLVE", &op.resolve, |o| {
            o.resolve.set(op.resolve.iter().copied()).map_err(oom)
        })?;
    }
    if !op.connect_to.is_empty() {
        s.slist("CURLOPT_CONNECT_TO", &op.connect_to, |o| {
            o.connect_to.set(op.connect_to.iter().copied()).map_err(oom)
        })?;
    }
    if let Some(set) = op.protocols {
        let list = set.list().map_err(oom)?;
        s.str("CURLOPT_PROTOCOLS_STR", Some(&list), |o| {
            o.schemes.make_mut().map_err(oom)?.allowed = set.schemes();
            Ok(())
        })?;
    }
    if let Some(set) = op.redirect_protocols {
        let list = set.list().map_err(oom)?;
        s.str("CURLOPT_REDIR_PROTOCOLS_STR", Some(&list), |o| {
            o.schemes.make_mut().map_err(oom)?.redirect = set.schemes();
            Ok(())
        })?;
    }
    let default = op.default_protocol;
    s.str(
        "CURLOPT_DEFAULT_PROTOCOL",
        default.map(|d| d.given),
        |o| match default {
            Some(d) => o
                .set_default_protocol(Some(d.protocol.name().as_bytes()))
                .map_err(oom),
            None => Ok(()),
        },
    )?;
    // A delay of C's default is not set.
    if let Some(ms) = op.happy_eyeballs_ms.filter(|&ms| ms != 200) {
        s.long("CURLOPT_HAPPY_EYEBALLS_TIMEOUT_MS", long(ms), |o| {
            o.limits.eyeballs = options::EyeballsDelay(Duration::from_millis(ms));
            Ok(())
        })?;
    }
    s.long(
        "CURLOPT_DISALLOW_USERNAME_IN_URL",
        i64::from(op.disallow_username),
        |o| {
            o.url_rules.disallow_user = op.disallow_username;
            Ok(())
        },
    )?;
    if op.ip_tos > 0 || op.vlan_priority > 0 {
        let marking = crate::sockopt::Marking {
            type_of_service: op.ip_tos,
            priority: op.vlan_priority,
            msgs: run.msgs,
        };
        s.ptr("CURLOPT_SOCKOPTFUNCTION", Function, |o| {
            let configurer = Handler::socket_configurer(marking).map_err(oom)?;
            o.sockets.make_mut().map_err(oom)?.configure = Some(configurer);
            Ok(())
        })?;
        s.ptr("CURLOPT_SOCKOPTDATA", Object, nothing)?;
    }
    Ok(())
}

/// The proxy options (`proxy_setopts`), made only where one is given.
fn proxy_setopts(s: &mut Setopt<'_>, op: &Operation<'_>) -> Result<(), ErrorKind> {
    if let Some(proxy) = op.proxy {
        s.str("CURLOPT_PROXY", Some(proxy), |o| {
            o.proxy.make_mut().map_err(oom)?.url = Some(copy(proxy).map_err(oom)?);
            Ok(())
        })?;
        s.enumerated(
            "CURLOPT_PROXYTYPE",
            easysrc::PROXY_TYPES,
            easysrc::proxy_type(op.proxy_kind),
            |o| {
                o.proxy.make_mut().map_err(oom)?.kind = op.proxy_kind;
                Ok(())
            },
        )?;
    }
    let user = op.proxy_user.as_deref();
    s.str("CURLOPT_PROXYUSERPWD", user, |o| {
        let Some(pair) = user else {
            return Ok(());
        };
        let set = match o.proxy.make_mut() {
            Ok(proxy) => proxy.set_user_password(Some(pair)),
            Err(OutOfMemory) => Err(options::ProxyUserError::OutOfMemory),
        };
        set.map_err(|e| match e {
            options::ProxyUserError::OutOfMemory => ErrorKind::OutOfMemory,
            options::ProxyUserError::Malformed => ErrorKind::UrlMalformat,
        })
    })?;
    s.long("CURLOPT_HTTPPROXYTUNNEL", i64::from(op.proxytunnel), |o| {
        if op.proxytunnel {
            o.proxy.make_mut().map_err(oom)?.tunnel = true;
        }
        Ok(())
    })?;
    if let Some(pre) = op.preproxy {
        s.str("CURLOPT_PRE_PROXY", Some(pre), |o| {
            o.proxy.make_mut().map_err(oom)?.pre_proxy = Some(copy(pre).map_err(oom)?);
            Ok(())
        })?;
    }
    // One method, in C's order.
    let proxy_auth = if op.proxy_anyauth {
        Some(options::AuthMethods::ANY)
    } else if op.proxy_digest {
        Some(options::AuthMethods::DIGEST)
    } else if op.proxy_basic {
        Some(options::AuthMethods::BASIC)
    } else {
        None
    };
    if let Some(methods) = proxy_auth {
        s.bitmask(
            "CURLOPT_PROXYAUTH",
            easysrc::AUTH,
            easysrc::auth_mask(methods),
            |o| {
                o.proxy.make_mut().map_err(oom)?.auth = options::HttpAuth(methods);
                Ok(())
            },
        )?;
    }
    s.str("CURLOPT_NOPROXY", op.noproxy, |o| {
        if let Some(no) = op.noproxy {
            o.proxy.make_mut().map_err(oom)?.no_proxy = Some(copy(no).map_err(oom)?);
        }
        Ok(())
    })?;
    // The debug test build suppresses them on request as well, as C's
    // library does.
    let suppress = op.suppress_connect_headers
        || (cfg!(feature = "debug-hooks")
            && curl_os::env::is_set(b"CURL_DBG_SUPPRESS_CONNECT_HDS"));
    s.long(
        "CURLOPT_SUPPRESS_CONNECT_HEADERS",
        i64::from(op.suppress_connect_headers),
        |o| {
            if suppress {
                o.proxy.make_mut().map_err(oom)?.suppress_connect_headers = true;
            }
            Ok(())
        },
    )?;
    if op.haproxy_protocol {
        s.long("CURLOPT_HAPROXYPROTOCOL", 1, |o| {
            o.proxy.make_mut().map_err(oom)?.haproxy = true;
            Ok(())
        })?;
    }
    if let Some(ip) = op.haproxy_clientip {
        // As C's library takes it: an address turns the protocol on.
        s.str("CURLOPT_HAPROXY_CLIENT_IP", Some(ip), |o| {
            let p = o.proxy.make_mut().map_err(oom)?;
            p.haproxy = true;
            p.haproxy_client_ip = Some(copy(ip).map_err(oom)?);
            Ok(())
        })?;
    }
    Ok(())
}

/// Who the transfer is, and its headers (`credentials_and_headers_setopts`).
fn credentials_and_headers(
    s: &mut Setopt<'_>,
    op: &Operation<'_>,
    etag: Option<&[u8]>,
) -> Result<(), ErrorKind> {
    s.str("CURLOPT_XOAUTH2_BEARER", op.bearer, |o| {
        if let Some(token) = op.bearer {
            o.login.make_mut().map_err(oom)?.bearer = Some(copy(token).map_err(oom)?);
        }
        Ok(())
    })?;
    let (netrc, value) = if op.netrc_optional {
        (options::NetrcMode::Optional, 1)
    } else if op.netrc || op.netrc_file.is_some() {
        (options::NetrcMode::Required, 2)
    } else {
        (options::NetrcMode::Ignored, 0)
    };
    s.enumerated("CURLOPT_NETRC", easysrc::NETRC, value, |o| {
        if netrc != options::NetrcMode::Ignored {
            o.netrc.make_mut().map_err(oom)?.mode = netrc;
        }
        Ok(())
    })?;
    s.str("CURLOPT_NETRC_FILE", op.netrc_file, |o| {
        if let Some(file) = op.netrc_file {
            o.netrc.make_mut().map_err(oom)?.file = Some(copy(file).map_err(oom)?);
        }
        Ok(())
    })?;
    // A user given without a password has had one asked for.
    let user = op.user.as_deref();
    s.str("CURLOPT_USERPWD", user, |o| {
        if let Some(pair) = user {
            let given = options::Login::from_pair(pair).map_err(oom)?;
            let login = o.login.make_mut().map_err(oom)?;
            login.user = given.user;
            login.password = given.password;
        }
        Ok(())
    })?;
    if !op.auth.is_empty() {
        s.bitmask(
            "CURLOPT_HTTPAUTH",
            easysrc::AUTH,
            easysrc::auth_mask(op.auth),
            |o| {
                o.http.auth = options::HttpAuth(op.auth);
                Ok(())
            },
        )?;
    }
    // `--json` types the request and accepts JSON, unless the headers
    // say otherwise (`get_args`).
    let json = [
        (&b"Content-Type"[..], &b"Content-Type: application/json"[..]),
        (b"Accept", b"Accept: application/json"),
    ]
    .map(|(name, line)| (op.json && !in_list(&op.headers, name)).then_some(line));
    let mut headers = Vec::new();
    headers
        .try_reserve_exact(op.headers.len() + 3)
        .map_err(|_| ErrorKind::OutOfMemory)?;
    let lines = op.headers.iter().copied().chain(json.into_iter().flatten());
    for line in lines.chain(etag) {
        headers.try_push(line).map_err(oom)?;
    }
    s.slist("CURLOPT_HTTPHEADER", &headers, |o| {
        o.http.headers = options::UserHeaders::new(headers.iter().copied()).map_err(oom)?;
        Ok(())
    })?;
    s.str("CURLOPT_REFERER", op.referer, |o| {
        let value = op.referer.map(copy).transpose().map_err(oom)?;
        o.http.custom.set(|g| &mut g.referer, value).map_err(oom)?;
        Ok(())
    })?;
    let default_agent;
    let agent = match op.user_agent {
        Some(agent) => agent,
        None => {
            default_agent = try_format(format_args!(
                "curl/{}",
                curl_core::version::version().version
            ))
            .map_err(oom)?;
            default_agent.as_bytes()
        }
    };
    s.str("CURLOPT_USERAGENT", Some(agent), |o| {
        o.http.user_agent = Some(copy(agent).map_err(oom)?);
        Ok(())
    })
}

/// What is transferred, and how (`transfer_setopts`).
fn transfer_setopts(
    s: &mut Setopt<'_>,
    op: &Operation<'_>,
    run: &Shared<'_, '_>,
    config: &Config<'_>,
) -> Result<(), ErrorKind> {
    s.long("CURLOPT_NOBODY", i64::from(op.no_body), |o| {
        if op.no_body {
            o.method = Method::Head;
        }
        Ok(())
    })?;
    let fail = op.fail == Fail::WithoutBody;
    s.long("CURLOPT_FAILONERROR", i64::from(fail), |o| {
        o.http.fail_on_error = fail;
        Ok(())
    })?;
    s.str("CURLOPT_REQUEST_TARGET", op.request_target, |o| {
        let value = op.request_target.map(copy).transpose().map_err(oom)?;
        o.http.custom.set(|g| &mut g.target, value).map_err(oom)?;
        Ok(())
    })?;
    s.long("CURLOPT_UPLOAD", i64::from(config.upload), |o| {
        if config.upload {
            o.method = Method::Upload;
        }
        Ok(())
    })?;
    s.str("CURLOPT_RANGE", op.range.as_deref(), |o| {
        o.range = op.range.as_deref().map(copy).transpose().map_err(oom)?;
        Ok(())
    })?;
    s.ptr("CURLOPT_ERRORBUFFER", easysrc::Pointer::Object, nothing)?;
    s.long("CURLOPT_TIMEOUT_MS", long(op.timeout_ms), |o| {
        o.limits.total = TimeLimit::from_millis(op.timeout_ms);
        Ok(())
    })?;
    // `setopt_post`.
    if let Some(post) = config.post {
        s.postfields(post, |o| {
            o.method = Method::Post;
            let body = copy(post).map_err(oom)?;
            o.upload = options::UploadSource::Bytes(TryArc::try_new(body).map_err(oom)?);
            Ok(())
        })?;
        s.offt(
            "CURLOPT_POSTFIELDSIZE_LARGE",
            long(post.len() as u64),
            nothing,
        )?;
    } else if let (Some(tree), Some(form)) = (&config.form, &op.form) {
        s.mimepost(form, |o| {
            o.method = Method::Post;
            let tree = curl_core::mime::Fixed::new(tree.clone());
            o.upload = options::UploadSource::Mime(Handler::mime(tree).map_err(oom)?);
            Ok(())
        })?;
    }
    if op.form_escape {
        s.long("CURLOPT_MIME_OPTIONS", 1, |o| {
            o.mime.make_mut().map_err(oom)?.form_escape = true;
            Ok(())
        })?;
    }
    s.long("CURLOPT_LOW_SPEED_LIMIT", long(op.low_speed_limit), nothing)?;
    s.long("CURLOPT_LOW_SPEED_TIME", long(op.low_speed_time), |o| {
        o.flow
            .set(
                |g| &mut g.low_speed,
                low_speed(op.low_speed_limit, op.low_speed_time),
            )
            .map_err(oom)?;
        Ok(())
    })?;
    s.offt("CURLOPT_MAX_SEND_SPEED_LARGE", long(op.limit_rate), |o| {
        o.flow
            .set(|g| &mut g.max_send_speed, NonZeroU64::new(op.limit_rate))
            .map_err(oom)?;
        Ok(())
    })?;
    s.offt("CURLOPT_MAX_RECV_SPEED_LARGE", long(op.limit_rate), |o| {
        o.flow
            .set(|g| &mut g.max_recv_speed, NonZeroU64::new(op.limit_rate))
            .map_err(oom)?;
        Ok(())
    })?;
    // An upload resumed where the peer's file ends is -1.
    let resume_from = match config.resume {
        None => 0,
        Some(options::Resume::At(n)) => long(n.get()),
        Some(options::Resume::AtEnd) => -1,
    };
    s.offt("CURLOPT_RESUME_FROM_LARGE", resume_from, |o| {
        o.resume = config.resume;
        Ok(())
    })?;
    if op.path_as_is {
        s.long("CURLOPT_PATH_AS_IS", 1, |o| {
            o.url_rules.path_as_is = true;
            Ok(())
        })?;
    }
    if op.no_body || op.remote_time {
        s.long("CURLOPT_FILETIME", 1, |o| {
            o.filetime = true;
            Ok(())
        })?;
    }
    let (condition, time) = match op.time_cond {
        None => (0, 0),
        Some(c) => (
            match c.when {
                options::Condition::ModifiedSince => 1,
                options::Condition::UnmodifiedSince => 2,
                options::Condition::LastModified => 3,
            },
            c.time,
        ),
    };
    s.enumerated(
        "CURLOPT_TIMECONDITION",
        easysrc::TIME_CONDITIONS,
        condition,
        |o| {
            o.time_condition = op.time_cond;
            Ok(())
        },
    )?;
    s.offt("CURLOPT_TIMEVALUE_LARGE", time, nothing)?;
    s.str("CURLOPT_CUSTOMREQUEST", op.custom_request, |o| {
        let value = op.custom_request.map(copy).transpose().map_err(oom)?;
        o.http.custom.set(|g| &mut g.method, value).map_err(oom)?;
        Ok(())
    })?;
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
    Ok(())
}

/// The speed `--speed-limit` and `--speed-time` ask a transfer to keep
/// up, if both are set. A time longer than the library keeps, some 18
/// hours, is taken as that.
fn low_speed(limit: u64, time: u64) -> Option<options::LowSpeed> {
    Some(options::LowSpeed {
        limit: NonZeroU64::new(limit)?,
        time: NonZeroU16::new(u16::try_from(time).unwrap_or(u16::MAX))?,
    })
}

/// Reads of 100 KiB, or of a receive rate `limit_rate` under that, so a
/// limited transfer reads no more than it may at once (`buffersize`).
fn buffer_size(limit_rate: u64) -> u64 {
    match limit_rate {
        rate @ 1..TOOL_BUFFER => rate,
        _ => TOOL_BUFFER,
    }
}

/// The options only a URL the tool takes for HTTP's is given
/// (`http_setopts`, `cookie_setopts`).
fn http_setopts(
    s: &mut Setopt<'_>,
    op: &Operation<'_>,
    tls: bool,
    msgs: &Messages,
) -> Result<(), ErrorKind> {
    let follow = match op.follow {
        options::Follow::No => 0,
        options::Follow::All => 1,
        options::Follow::ObeyCode => 2,
        options::Follow::FirstOnly => 3,
    };
    s.long("CURLOPT_FOLLOWLOCATION", follow, |o| {
        o.http.follow = op.follow;
        Ok(())
    })?;
    s.long(
        "CURLOPT_UNRESTRICTED_AUTH",
        i64::from(op.unrestricted_auth),
        |o| {
            o.http.unrestricted_auth = op.unrestricted_auth;
            Ok(())
        },
    )?;
    // As `CURLOPT_AWS_SIGV4` takes it, after the methods: given, it is
    // the one method; not, it is none of them.
    s.str("CURLOPT_AWS_SIGV4", op.aws_sigv4, |o| {
        let http = &mut o.http;
        http.signing
            .set(
                |g| &mut g.aws_sigv4,
                op.aws_sigv4.map(copy).transpose().map_err(oom)?,
            )
            .map_err(oom)?;
        http.auth.0 = match op.aws_sigv4 {
            Some(_) => options::AuthMethods::AWS_SIGV4,
            None => http.auth.0 & !options::AuthMethods::AWS_SIGV4,
        };
        Ok(())
    })?;
    message_signature(s, op.httpsig, msgs)?;
    s.long("CURLOPT_AUTOREFERER", i64::from(op.auto_referer), |o| {
        o.http.auto_referer = op.auto_referer;
        Ok(())
    })?;
    if !op.proxy_headers.is_empty() {
        s.slist("CURLOPT_PROXYHEADER", &op.proxy_headers, |o| {
            o.proxy.make_mut().map_err(oom)?.headers =
                options::UserHeaders::new(op.proxy_headers.iter().copied()).map_err(oom)?;
            Ok(())
        })?;
    }
    // As `CURLOPT_MAXREDIRS` takes it: -1 no limit, at most 32767.
    let max_redirs = op.max_redirs.unwrap_or(50);
    s.long("CURLOPT_MAXREDIRS", max_redirs, |o| {
        o.http.max_redirects = options::MaxRedirects(match max_redirs {
            -1 => None,
            n => Some(u16::try_from(n.clamp(0, 0x7fff)).expect("clamped")),
        });
        Ok(())
    })?;
    if let Some(version) = op.http_version {
        let (version, value) = match version {
            HttpVersion::Http10 => (options::HttpVersion::Http10, 1),
            HttpVersion::Http11 => (options::HttpVersion::Http11, 2),
        };
        s.enumerated("CURLOPT_HTTP_VERSION", easysrc::HTTP_VERSIONS, value, |o| {
            o.http.version = version;
            Ok(())
        })?;
    }
    let redir = op.post_redirect;
    let mask =
        i64::from(redir.post301) | i64::from(redir.post302) << 1 | i64::from(redir.post303) << 2;
    s.long("CURLOPT_POSTREDIR", mask, |o| {
        o.http.post_redirect = redir;
        Ok(())
    })?;
    if op.compressed {
        s.str("CURLOPT_ACCEPT_ENCODING", Some(b""), |o| {
            o.http.accept_encoding = Some(curl_core::coding::AcceptEncoding::All);
            Ok(())
        })?;
    }
    if op.tr_encoding {
        s.long("CURLOPT_TRANSFER_ENCODING", 1, |o| {
            o.http.transfer_encoding = true;
            Ok(())
        })?;
    }
    s.long("CURLOPT_HTTP09_ALLOWED", i64::from(op.http09), |o| {
        o.http.allow_09 = op.http09;
        Ok(())
    })?;
    if op.expect100_timeout_ms > 0 {
        let ms = op.expect100_timeout_ms;
        s.long("CURLOPT_EXPECT_100_TIMEOUT_MS", long(ms), |o| {
            // As `CURLOPT_EXPECT_100_TIMEOUT_MS` takes it, at most 65535.
            o.http.continue_wait = options::ContinueWait(Duration::from_millis(ms.min(0xffff)));
            Ok(())
        })?;
    }
    // `cookie_setopts`. The cookie options are made only where one is
    // given, as C's library keeps none it is not given.
    if let Some(send) = joined_cookies(&op.cookies, msgs)? {
        s.str("CURLOPT_COOKIE", Some(&send), |o| {
            o.http.cookies.make_mut().map_err(oom)?.send = Some(copy(&send).map_err(oom)?);
            Ok(())
        })?;
    }
    for &file in &op.cookie_files {
        s.str("CURLOPT_COOKIEFILE", Some(file), |o| {
            o.http
                .cookies
                .make_mut()
                .map_err(oom)?
                .files
                .push(file)
                .map_err(oom)
        })?;
    }
    s.str("CURLOPT_COOKIEJAR", op.cookie_jar, |o| {
        if let Some(jar) = op.cookie_jar {
            o.http.cookies.make_mut().map_err(oom)?.save_to = Some(copy(jar).map_err(oom)?);
        }
        Ok(())
    })?;
    s.long("CURLOPT_COOKIESESSION", i64::from(op.cookie_session), |o| {
        if op.cookie_session {
            o.http.cookies.make_mut().map_err(oom)?.new_session = true;
        }
        Ok(())
    })?;
    // The headers for the origin are kept from a proxy that tunnels, as
    // the library does unless told otherwise.
    if (op.proxy.is_some() || !op.proxy_headers.is_empty()) && (tls || op.proxytunnel) {
        s.long("CURLOPT_HEADEROPT", 1, nothing)?;
    }
    Ok(())
}

/// What an HTTP message signature signs with, if any of it is given, as
/// `httpsig_setopts` sets it after the other HTTP options: the key and
/// its name required, the algorithm Ed25519 unless given, and the key
/// read from a file for `@` and its name. What is wrong is said here.
fn message_signature(
    s: &mut Setopt<'_>,
    given: Httpsig<'_>,
    msgs: &Messages,
) -> Result<(), ErrorKind> {
    use options::SignatureAlgorithm as A;
    if given == Httpsig::default() {
        return Ok(());
    }
    let Some(key) = given.key else {
        msgs.error(&[b"--httpsig-key is required"]);
        return Err(ErrorKind::FailedInit);
    };
    let Some(key_id) = given.key_id else {
        msgs.error(&[b"--httpsig-keyid is required"]);
        return Err(ErrorKind::FailedInit);
    };
    let (algorithm, value) = match given.algorithm {
        None => (A::Ed25519, 1),
        Some(name) if name.eq_ignore_ascii_case(b"ed25519") => (A::Ed25519, 1),
        Some(name) if name.eq_ignore_ascii_case(b"hmac-sha256") => (A::HmacSha256, 2),
        Some(name) => {
            msgs.error(&[b"--httpsig-algo: unsupported algorithm '", name, b"'"]);
            return Err(ErrorKind::FailedInit);
        }
    };
    s.long("CURLOPT_HTTPSIG_ALGORITHM", value, |o| {
        o.http.auth.0 = options::AuthMethods::HTTPSIG;
        o.http.signing.make_mut().map_err(oom)?.message.algorithm = Some(algorithm);
        Ok(())
    })?;
    s.str("CURLOPT_HTTPSIG_HEADERS", given.components, |o| {
        o.http.signing.make_mut().map_err(oom)?.message.components =
            given.components.map(copy).transpose().map_err(oom)?;
        Ok(())
    })?;
    s.str("CURLOPT_HTTPSIG_KEYID", Some(key_id), |o| {
        o.http.signing.make_mut().map_err(oom)?.message.key_id = Some(copy(key_id).map_err(oom)?);
        Ok(())
    })?;
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
    s.str("CURLOPT_HTTPSIG_KEY", Some(&key), |o| {
        o.http.signing.make_mut().map_err(oom)?.message.key = Some(copy(&key).map_err(oom)?);
        Ok(())
    })
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
    url: Given<'_>,
    easy: &Easy,
    out: &output::Output,
    bar: Option<&Bar>,
    ended: Ended,
) -> Result<(), ErrorKind> {
    let msgs = run.msgs;
    let mut skipped = Ok(());
    let (result, retries) = match ended {
        Ended::Ran(result) => {
            let result = settle(op, run, url.text, easy, out, result, Told::Not);
            (Some(result), 0)
        }
        Ended::Said(e) => {
            let result = settle(op, run, url.text, easy, out, Err(e), Told::Already);
            (Some(result), 0)
        }
        Ended::Settled(result, retries) => (Some(result), retries),
        Ended::Skipped(result) => {
            skipped = result;
            (None, 0)
        }
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
        None => skipped,
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

/// How a failure's reason is told.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Told<'w> {
    /// Not yet: the transfer's reason is.
    Not,
    /// By the tool, already (C's `synthetic_error`).
    Already,
    /// As this, in place of the transfer's (C's tool writing the error
    /// buffer).
    As(&'w [u8]),
}

/// What one attempt's `result` comes to (`post_check_result`,
/// `post_output_handling`): its failure said, a failing response with
/// `--fail-with-body` made one, where the file of `url` came from stored
/// with it, an output file that got nothing created, and standard output
/// flushed.
fn settle(
    op: &Operation<'_>,
    run: &Shared<'_, '_>,
    url: &[u8],
    easy: &Easy,
    out: &output::Output,
    mut result: Result<(), ErrorKind>,
    told: Told<'_>,
) -> Result<(), ErrorKind> {
    let msgs = run.msgs;
    // The transfer's reason, or the kind's, unless the tool said its own.
    if let Err(e) = result
        && told != Told::Already
        && let Ok(code) = try_format(format_args!("curl: ({}) ", exit_code(e)))
    {
        let why = match told {
            Told::As(why) => Some(why),
            Told::Not | Told::Already => easy.report().failure(),
        };
        match why {
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
    // `--xattr`, for a file the transfer opened.
    if result.is_ok()
        && op.xattr
        && let Some(file) = stream.open_file()
        && let Err(e) = crate::xattr::write(file.as_fd(), url, easy.report(), run.stdout)
    {
        let name = stream.file_name().unwrap_or_default();
        msgs.warn(&[
            b"Error setting extended attributes on '",
            name,
            b"': ",
            os_message(&e).as_bytes(),
        ]);
    }
    // A successful transfer that wrote nothing still leaves its output
    // file, empty, unless a time condition kept the file from coming or
    // the server answered 304: then the file is not even replaced.
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
    /// HTTP, or with `tls` HTTPS.
    Http { tls: bool },
    /// IPFS or IPNS, which go to a gateway.
    Ipfs(crate::ipfs::Kind),
    /// Another, or none it knows.
    Other,
}

/// What a URL whose scheme could not be had for `e` is taken to be: one
/// of no protocol the tool knows, unless memory ran out.
fn no_proto(e: UrlErrorKind) -> Result<(UrlProto, Option<Url>), OutOfMemory> {
    match e {
        UrlErrorKind::OutOfMemory => Err(OutOfMemory),
        _ => Ok((UrlProto::Other, None)),
    }
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
    let url = match Url::parse(url, parse) {
        Ok(url) => url,
        Err(e) => return no_proto(e),
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
        (Err(e), _) => return no_proto(e),
    };
    if let Some(kind) = crate::ipfs::Kind::of_scheme(&scheme) {
        return Ok((UrlProto::Ipfs(kind), Some(url)));
    }
    let proto = if scheme.eq_ignore_ascii_case(b"http") {
        UrlProto::Http { tls: false }
    } else if scheme.eq_ignore_ascii_case(b"https") {
        UrlProto::Http { tls: true }
    } else {
        UrlProto::Other
    };
    Ok((proto, None))
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

/// Upload `source`, its size said if known (`pre_transfer`).
fn upload_setopts(
    easy: &mut Easy,
    run: &Shared<'_, '_>,
    source: UploadSource,
) -> Result<(), ErrorKind> {
    let size = match &source {
        UploadSource::Read { size, .. } => *size,
        _ => None,
    };
    let mut program = run.libcurl.map(RefCell::borrow_mut);
    let mut s = Setopt::new(easy, program.as_deref_mut());
    // C sets no size it does not know.
    match size {
        Some(size) => s.offt("CURLOPT_INFILESIZE_LARGE", long(size), |o| {
            o.upload = source;
            Ok(())
        }),
        None => s.unwritten("the read callback reads it", |o| {
            o.upload = source;
            Ok(())
        }),
    }
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

/// What the libraries this build is linked with do for a handle, as C's:
/// the content codings they undo, the signatures they make.
static LIBRARIES: curl_core::libraries::Libraries = {
    use curl_core::coding::{Coding, Decoders};
    curl_core::libraries::Libraries {
        decoders: Decoders::none()
            .with(Coding::Deflate, curl_zlib::deflate)
            .with(Coding::Gzip, curl_zlib::gzip)
            .with(Coding::Brotli, curl_brotli::decoder)
            .with(Coding::Zstd, curl_zstd::decoder),
        ed25519: Some(&curl_openssl::ED25519),
    }
};

#[cfg(test)]
mod tests {
    use super::*;

    /// A fatal error ends the run, and with `--fail-early` any failure.
    #[test]
    fn ends_the_run_as_c_does() {
        let failed = Err(ErrorKind::CouldntConnect);
        assert!(!ends_run(Ok(()), true));
        assert!(!ends_run(failed, false));
        assert!(ends_run(failed, true));
        assert!(ends_run(Err(ErrorKind::OutOfMemory), false));
    }

    /// `--rate`'s wait: what is left of its time, if any.
    #[test]
    fn waits_what_is_left_of_the_rate() {
        assert_eq!(rate_left(0, 0), None);
        assert_eq!(rate_left(1000, 300), Some(700));
        assert_eq!(rate_left(1000, 999), Some(1));
        assert_eq!(rate_left(1000, 1000), None);
        assert_eq!(rate_left(1000, 5000), None);
    }

    /// `--rate` waits what is left of its time, noted when tracing.
    #[test]
    fn waits_for_the_rate_and_says_so() {
        let start = Instant::now();
        let said = crate::msgs::captured(|mut msgs| {
            msgs.tracing = true;
            rate_wait(300, Some(start), msgs);
        });
        assert!(start.elapsed() >= Duration::from_millis(300));
        assert!(said.starts_with("Note: Transfer took "), "{said}");
        assert!(said.ends_with("ms as set by --rate\n"), "{said}");
        let first = Instant::now();
        let said = crate::msgs::captured(|mut msgs| {
            msgs.tracing = true;
            rate_wait(300, None, msgs);
        });
        assert!(first.elapsed() < Duration::from_millis(300));
        assert_eq!(said, "");
    }

    /// `--speed-limit` and `--speed-time` both, or no check; a time past
    /// what the library keeps is the longest it does.
    #[test]
    fn asks_for_a_low_speed_with_both() {
        let low = |limit, time| low_speed(limit, time).map(|l| (l.limit.get(), l.time.get()));
        assert_eq!(low(100, 30), Some((100, 30)));
        assert_eq!(low(0, 30), None);
        assert_eq!(low(1, 0), None);
        assert_eq!(low(1, 70_000), Some((1, u16::MAX)));
    }

    /// `retrycheck`'s reasons: failures that may pass, the HTTP codes that
    /// say so (with `--fail`, as its failure too), and with
    /// `--retry-all-errors` any failure.
    #[test]
    fn retries_for_c_reasons() {
        let mut op = Operation::default();
        let http = Some(Protocol::Http);
        let timed_out = Err(ErrorKind::OperationTimedout);
        assert_eq!(
            reason(&op, timed_out, None, None, None),
            Some(Reason::Timeout)
        );
        let resolve = Err(ErrorKind::CouldntResolveHost);
        assert_eq!(
            reason(&op, resolve, None, None, None),
            Some(Reason::Timeout)
        );
        for code in [408, 429, 500, 502, 503, 504, 522, 524] {
            assert_eq!(
                reason(&op, Ok(()), http, Some(code), None),
                Some(Reason::Http)
            );
        }
        for code in [200, 404, 501, 505, 523] {
            assert_eq!(reason(&op, Ok(()), http, Some(code), None), None, "{code}");
        }
        assert_eq!(reason(&op, Ok(()), None, Some(503), None), None);
        let failed = Err(ErrorKind::HttpReturnedError);
        assert_eq!(reason(&op, failed, http, Some(503), None), None);
        op.fail = Fail::WithoutBody;
        assert_eq!(
            reason(&op, failed, http, Some(503), None),
            Some(Reason::Http)
        );
        let refused = Err(ErrorKind::CouldntConnect);
        assert_eq!(reason(&op, refused, http, None, None), None);
        // Refused, with `--retry-connrefused`; and not otherwise.
        // As Linux numbers them.
        let why = OsErrno::new(111);
        assert_eq!(reason(&op, refused, http, None, why), None);
        op.retry_connrefused = true;
        assert_eq!(
            reason(&op, refused, http, None, why),
            Some(Reason::ConnRefused)
        );
        let timed_out_connect = OsErrno::new(110);
        assert_eq!(reason(&op, refused, http, None, timed_out_connect), None);
        assert_eq!(
            reason(&op, Ok(()), http, Some(503), why),
            Some(Reason::Http)
        );
        op.retry_all_errors = true;
        assert_eq!(
            reason(&op, refused, http, None, None),
            Some(Reason::AllErrors)
        );
        assert_eq!(reason(&op, Ok(()), http, Some(404), None), None);
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
        let http = |url: &str, default| matches!(proto(url, default), UrlProto::Http { .. });
        assert_eq!(proto("http://h/", None), UrlProto::Http { tls: false });
        assert_eq!(proto("HTTPS://h/", None), UrlProto::Http { tls: true });
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
        // Memory running out is said, as C's `CURLUE_OUT_OF_MEMORY` is.
        assert!(matches!(
            no_proto(UrlErrorKind::OutOfMemory),
            Err(OutOfMemory)
        ));
        assert!(matches!(
            no_proto(UrlErrorKind::MalformedInput),
            Ok((UrlProto::Other, None))
        ));
    }

    /// `buffersize`: 100 KiB, or a receive rate under that, as the core
    /// takes it.
    #[test]
    fn reads_no_more_than_the_rate_at_once() {
        for (rate, size) in [
            (0, 102_400),
            (1, 1024),
            (5000, 5000),
            (102_399, 102_399),
            (102_400, 102_400),
            (1 << 40, 102_400),
        ] {
            let set = options::BufferSize::clamped(buffer_size(rate));
            assert_eq!(set.get(), size, "{rate}");
        }
    }

    /// What `--libcurl` writes for the transfer `args` set up, as
    /// `config2setopts` sets it, and the options it was set up with.
    fn set_up(args: &[&str]) -> Option<(String, String)> {
        set_up_url(args, "http://h/")
    }

    /// What `--libcurl` writes for `args` and `url`, as `set_up`.
    fn set_up_url(args: &[&str], url: &str) -> Option<(String, String)> {
        let argv: Vec<std::ffi::OsString> = std::iter::once("curl")
            .chain(args.iter().copied())
            .chain(std::iter::once(url))
            .map(std::ffi::OsString::from)
            .collect();
        let mut msgs = Messages::new();
        msgs.silent = true;
        let line = match tool::parse_args(&argv, &mut msgs, &mut |_, _| {}) {
            Ok(tool::Parsed::Run(line)) if line.unimplemented.is_none() => line,
            _ => return None,
        };
        let op = line.operations.last()?;
        let stdout = Stdout::new().unwrap();
        let tracer = Tracer::new(&line.global, &stdout).unwrap();
        let share = Share::new().unwrap();
        let suffixes = curl_psl::suffixes().unwrap();
        let program = RefCell::new(Source::new().unwrap());
        let run = Shared {
            libcurl: Some(&program),
            global: &line.global,
            stdout: &stdout,
            tracer: tracer.as_ref(),
            msgs,
            share: &share,
            suffixes: &suffixes,
            started: Cell::new(None),
        };
        let out = output::Output::null(msgs).unwrap();
        let post = op.post.as_deref().filter(|_| !op.get);
        let form = match (&op.form, op.method) {
            (Some(form), tool::Method::Mime) => {
                Some(TryArc::try_new(form.mime(&msgs).ok()?).unwrap())
            }
            _ => None,
        };
        let upload = op.nodes.first().and_then(|n| match n.upload {
            Upload::File(file) => Some(file),
            _ => None,
        });
        let config = Config {
            url: url.as_bytes(),
            etag: None,
            proto: url_proto(url.as_bytes(), None).unwrap().0,
            resume: match op.resume {
                Some(Resume::At(n)) => NonZeroU64::new(n).map(options::Resume::At),
                Some(Resume::FromOutput) if upload.is_some() => Some(options::Resume::AtEnd),
                _ => None,
            },
            upload: upload.is_some(),
            post,
            form,
            method: op.method,
            terminal: false,
            bar: None,
        };
        let mut easy = Easy::new();
        {
            let mut source = program.borrow_mut();
            let mut s = Setopt::new(&mut easy, Some(&mut source));
            setopts(&mut s, op, &run, &out, &config).ok()?;
        }
        if let Some(file) = upload {
            upload_setopts(&mut easy, &run, open_upload(file).ok()?).ok()?;
        }
        // As the run would: the options written as comments go before it.
        program.borrow_mut().perform().unwrap();
        let mut text = Vec::new();
        program.into_inner().finish_into(&mut text);
        Some((
            String::from_utf8(text).unwrap(),
            format!("{:?}", easy.options()),
        ))
    }

    /// What `--libcurl` writes for options set only in some cases, as
    /// `config2setopts.c` and `pre_transfer` set them.
    #[test]
    fn writes_what_c_writes() {
        let dir = std::env::temp_dir().join(format!("curl-tool-setopts-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join("up");
        std::fs::write(&file, b"0123456789").unwrap();
        let file = file.to_str().unwrap();
        let line = |l: &str| format!("  curl_easy_setopt(curl, {l});\n");
        let headeropt = line("CURLOPT_HEADEROPT, 1L");
        let filetime = line("CURLOPT_FILETIME, 1L");
        let eyeballs = "HAPPY_EYEBALLS";
        for (args, has, lacks) in [
            (
                &["--connect-to", "a:1:b:2"][..],
                vec![
                    line("CURLOPT_CONNECT_TO, slist1"),
                    "  slist1 = curl_slist_append(slist1, \"a:1:b:2\");\n".to_owned(),
                ],
                vec![],
            ),
            (
                &["--happy-eyeballs-timeout-ms", "300"],
                vec![line("CURLOPT_HAPPY_EYEBALLS_TIMEOUT_MS, 300L")],
                vec![],
            ),
            // C's default is not set.
            (
                &["--happy-eyeballs-timeout-ms", "200"],
                vec![],
                vec![eyeballs.to_owned()],
            ),
            // `tcp_setopts`: keepalive on, Nagle off by default.
            (
                &[],
                vec![line("CURLOPT_TCP_KEEPALIVE, 1L")],
                vec!["TCP_NODELAY".to_owned(), "KEEPIDLE".to_owned()],
            ),
            (&["--no-keepalive"], vec![], vec!["KEEPALIVE".to_owned()]),
            (
                &["--no-tcp-nodelay"],
                vec![line("CURLOPT_TCP_NODELAY, 0L")],
                vec![],
            ),
            (
                &["--keepalive-time", "30", "--keepalive-cnt", "4"],
                vec![
                    line("CURLOPT_TCP_KEEPIDLE, 30L"),
                    line("CURLOPT_TCP_KEEPINTVL, 30L"),
                    line("CURLOPT_TCP_KEEPCNT, 4L"),
                ],
                vec![],
            ),
            (
                &["--keepalive-time", "30", "--no-keepalive"],
                vec![],
                vec!["KEEPIDLE".to_owned()],
            ),
            (
                &["--tcp-fastopen"],
                vec![line("CURLOPT_TCP_FASTOPEN, 1L")],
                vec![],
            ),
            (
                &["--mptcp"],
                vec!["  CURLOPT_OPENSOCKETFUNCTION was set to a function pointer\n".to_owned()],
                vec![],
            ),
            (
                &["--ip-tos", "32"],
                vec![
                    "  CURLOPT_SOCKOPTFUNCTION was set to a function pointer\n".to_owned(),
                    "  CURLOPT_SOCKOPTDATA was set to an object pointer\n".to_owned(),
                ],
                vec![],
            ),
            (&["--ip-tos", "0"], vec![], vec!["SOCKOPT".to_owned()]),
            (&["-I"], vec![filetime.clone()], vec![]),
            (&["-R"], vec![filetime.clone()], vec![]),
            (&[], vec![], vec![filetime.clone(), headeropt.clone()]),
            // The origin's headers are kept from a tunnel's proxy.
            (&["-x", "http://p:3", "-p"], vec![headeropt.clone()], vec![]),
            (
                &["--proxy-header", "P: q", "-p"],
                vec![headeropt.clone()],
                vec![],
            ),
            (&["-x", "http://p:3"], vec![], vec![headeropt.clone()]),
            (&["-p"], vec![], vec![headeropt.clone()]),
            (
                &["-T", file, "-C", "-"],
                vec![
                    line("CURLOPT_UPLOAD, 1L"),
                    line("CURLOPT_RESUME_FROM_LARGE, (curl_off_t)-1"),
                    line("CURLOPT_INFILESIZE_LARGE, (curl_off_t)10"),
                ],
                vec![],
            ),
        ] {
            let (text, _) = set_up(args).unwrap();
            for want in has {
                assert!(text.contains(&want), "{args:?} lacks {want}\n{text}");
            }
            for unwanted in lacks {
                assert!(!text.contains(&unwanted), "{args:?} has {unwanted}\n{text}");
            }
        }
        // For HTTPS, a proxy keeps them without being told to tunnel.
        let (text, _) = set_up_url(&["-x", "http://p:3"], "https://h/").unwrap();
        assert!(text.contains(&headeropt), "{text}");
        let (text, _) = set_up_url(&[], "https://h/").unwrap();
        assert!(!text.contains(&headeropt), "{text}");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// The socket options reach the transfer as their lines say:
    /// keepalive on unless told otherwise, with the times and count
    /// given.
    #[test]
    fn sets_the_socket_options_it_writes() {
        let (_, on) = set_up(&["--keepalive-time", "7", "--keepalive-cnt", "3"]).unwrap();
        assert!(
            on.contains("keepalive: KeepAlive { on: true, idle: 7s, interval: 7s, count: 3 }"),
            "{on}"
        );
        let (_, off) = set_up(&["--no-keepalive", "--no-tcp-nodelay", "--tcp-fastopen"]).unwrap();
        assert!(
            off.contains("nodelay: false, keepalive: KeepAlive { on: false"),
            "{off}"
        );
        assert!(off.contains("fastopen: true"), "{off}");
    }

    /// Each option that changes what a transfer is set up with changes
    /// what `--libcurl` writes: an option is not set without its line.
    /// Options the C writes nothing for, as their value is the default,
    /// are listed.
    #[test]
    fn writes_each_option_it_sets() {
        // `CURLOPT_HTTP_CONTENT_DECODING` and `_TRANSFER_DECODING` are
        // set to 0, their default in C's eyes, and not written.
        let unwritten = ["raw"];
        let (base_text, base_options) = set_up(&[]).unwrap();
        let mut tried = 0;
        let mut changed = 0;
        for (name, kind) in tool::every_option() {
            // Those that read a file, run nothing, or point the test's own
            // standard error elsewhere.
            if [
                "config",
                "url",
                "next",
                "help",
                "version",
                "manual",
                "dump-ca-embed",
                "stderr",
            ]
            .contains(&name)
            {
                continue;
            }
            let flag = format!("--{name}");
            let values: &[&str] = if kind == tool::ArgKind::None || kind == tool::ArgKind::Bool {
                &[]
            } else {
                &["1", "a=b", "a:b", "x.y", "http://p/", "1 Jan 2020"]
            };
            let set = if values.is_empty() {
                set_up(&[&flag])
            } else {
                values.iter().find_map(|v| set_up(&[&flag, v]))
            };
            let Some((text, options)) = set else {
                continue;
            };
            tried += 1;
            if options != base_options {
                changed += 1;
                if !unwritten.contains(&name) {
                    assert_ne!(text, base_text, "--{name} sets an option it does not write");
                }
            }
        }
        // The needle: options were tried, and most change the transfer.
        assert!(tried > 100, "{tried} options tried");
        assert!(changed > 60, "{changed} options changed the transfer");
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
