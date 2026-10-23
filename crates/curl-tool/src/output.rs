//! Where a transfer's body and shown headers go: standard output, nowhere,
//! or a file, created when the first byte comes (`src/tool_cb_wrt.c`, and
//! the output side of `src/tool_cb_hdr.c`).

use core::ffi::CStr;
use std::fs::File;
use std::io::Write as _;
use std::sync::Mutex;

use curl_alloc::{OutOfMemory, TryArc, TryVec};
use curl_core::handler::{Handler, HeaderHandler, HeaderOrigin, Write, WriteHandler};
use curl_core::multi::TransferCx;
use curl_core::url::{GetOptions, ParseOptions, Part, SetOptions, Url};
use curl_core::version::Protocol;
use curl_os::fs::{self, Keep};

use crate::msgs::Messages;
use crate::options::Clobber;
use crate::os_message;
use crate::stdio::{self, Stdio};
use crate::stdout::Stdout;

/// What `fopen` creates a file with, before the umask.
const NEW_FILE_MODE: u32 = 0o666;

/// C's limit on binary bytes checked for, at the start of the output.
const BINARY_CHECK: u64 = 2000;

/// Starts header names on a terminal.
const BOLD: &[u8] = b"\x1b[1m";
/// Ends them: every attribute off, as not every terminal knows bold off.
const BOLD_OFF: &[u8] = b"\x1b[0m";
/// Starts a hyperlink's target, and ends one's text when the target is
/// empty (OSC 8).
const LINK: &[u8] = b"\x1b]8;;";
/// Ends a target.
const LINK_END: &[u8] = b"\x1b\\";

/// A transfer's output, shared by its write and header handlers and the
/// code that runs the transfer.
#[derive(Clone)]
pub(crate) struct Output(TryArc<Mutex<Stream>>);

/// Where output goes, and how (C's `struct OutStruct`).
pub(crate) struct Stream {
    target: Target,
    /// Bytes written since the file was opened or last kept
    /// (`outs->bytes`).
    bytes: u64,
    /// The file's size before them (`outs->init`).
    init: u64,
    /// Header lines are written too: `--include`.
    pub(crate) show_headers: bool,
    /// Standard output is a terminal: binary output is refused.
    pub(crate) terminal: bool,
    /// Header lines are styled for a terminal: their names bold, and a
    /// `Location:` a link (`isatty` and `styled_output`).
    pub(crate) styled: bool,
    /// `--output -`: binary output to a terminal is wanted.
    pub(crate) binary_ok: bool,
    /// `--no-buffer`: what is written is flushed at once.
    pub(crate) no_buffer: bool,
    /// `--clobber` or `--no-clobber`: whether a file that exists is
    /// emptied, or kept, the output going to the first free name numbered
    /// after it. A name the server gives is kept by default.
    pub(crate) clobber: Clobber,
    /// `--remote-header-name`: the file is named by the response, and the
    /// header lines to show wait until it is (`honor_cd_filename`).
    pub(crate) name_from_header: Option<FromHeader>,
    /// The file's name came from the response (`is_cd_filename`).
    server_named: bool,
    /// `--dump-header`: where header lines are written too.
    dump: Option<Dump>,
    /// Header lines with a colon in the last response's head
    /// (`per->num_headers`).
    num_headers: u64,
    /// The last header line was blank: the next starts a response.
    after_blank: bool,
    msgs: Messages,
}

/// A name the response is to give the output file, while it has not.
pub(crate) struct FromHeader {
    /// `--output-dir`, which the name goes in.
    pub(crate) dir: Option<Vec<u8>>,
    /// Header lines to show, held until the file is named (`headlist`).
    held: Vec<Vec<u8>>,
}

impl FromHeader {
    pub(crate) fn new(dir: Option<&[u8]>) -> Result<FromHeader, OutOfMemory> {
        let dir = match dir {
            Some(dir) => {
                let mut owned = Vec::new();
                owned.try_extend_from_slice(dir)?;
                Some(owned)
            }
            None => None,
        };
        Ok(FromHeader {
            dir,
            held: Vec::new(),
        })
    }
}

/// What a header line did to a name from the response.
enum Naming {
    /// It is held, to be shown once the file is named.
    Held,
    /// It goes on as any header line.
    Shown,
    Failed,
}

/// Where `--dump-header` writes, and the name it was given.
struct Dump {
    target: DumpTarget,
    name: Vec<u8>,
}

enum DumpTarget {
    Stdout(Stdout),
    Stderr,
    File(Stdio<File>),
}

impl DumpTarget {
    /// Write `line`: how much of it was taken (`fwrite`).
    fn fwrite(&mut self, line: &[u8]) -> usize {
        match self {
            DumpTarget::Stdout(out) => out.fwrite(line),
            // Standard error is unbuffered.
            DumpTarget::Stderr => unbuffered(&mut std::io::stderr(), line),
            DumpTarget::File(file) => file.fwrite(line),
        }
    }

    /// Write what is held (`fflush`).
    fn flush(&mut self) -> Result<(), stdio::Failed> {
        match self {
            DumpTarget::Stdout(out) => out.flush(),
            DumpTarget::Stderr => Ok(()),
            DumpTarget::File(file) => file.flush(),
        }
    }
}

/// Why `--dump-header`'s file could not be set up.
pub(crate) enum DumpFailed {
    OutOfMemory,
    /// It could not be opened; said already.
    Open,
}

enum Target {
    Stdout(Stdout),
    /// `--out-null`.
    Null,
    /// A file, by name with a zero byte after it; opened when needed, and
    /// written through stdio's buffer as C's `fopen`ed one is.
    File {
        name: Vec<u8>,
        file: Option<Stdio<File>>,
    },
}

impl Output {
    /// Output to standard output.
    pub(crate) fn stdout(stdout: &Stdout, msgs: Messages) -> Result<Output, OutOfMemory> {
        Output::new(Target::Stdout(stdout.clone()), msgs)
    }

    /// Output dropped.
    pub(crate) fn null(msgs: Messages) -> Result<Output, OutOfMemory> {
        Output::new(Target::Null, msgs)
    }

    /// Output to the file `name`, not opened yet.
    pub(crate) fn file(name: &[u8], msgs: Messages) -> Result<Output, OutOfMemory> {
        let mut owned = Vec::new();
        owned.try_extend_from_slice(name)?;
        owned.try_push(0)?;
        Output::new(
            Target::File {
                name: owned,
                file: None,
            },
            msgs,
        )
    }

    fn new(target: Target, msgs: Messages) -> Result<Output, OutOfMemory> {
        let stream = Stream {
            target,
            bytes: 0,
            init: 0,
            show_headers: false,
            terminal: false,
            styled: false,
            binary_ok: false,
            no_buffer: false,
            clobber: Clobber::Default,
            name_from_header: None,
            server_named: false,
            dump: None,
            num_headers: 0,
            after_blank: true,
            msgs,
        };
        Ok(Output(TryArc::try_new(Mutex::new(stream))?))
    }

    pub(crate) fn stream(&self) -> std::sync::MutexGuard<'_, Stream> {
        self.0.lock().expect("no panic holds it")
    }

    /// Write header lines to `name` too, as `--dump-header` asks: `-` is
    /// standard output and `%` standard error; a file is emptied first if
    /// `fresh`, then added to (`setup_headerfile`).
    pub(crate) fn dump_to(
        &self,
        name: &[u8],
        fresh: bool,
        stdout: &Stdout,
    ) -> Result<(), DumpFailed> {
        let mut owned = Vec::new();
        owned
            .try_extend_from_slice(name)
            .map_err(|OutOfMemory| DumpFailed::OutOfMemory)?;
        let mut stream = self.stream();
        let target = match name {
            b"%" => DumpTarget::Stderr,
            b"-" => DumpTarget::Stdout(stdout.clone()),
            _ => {
                let mut c_name = Vec::new();
                c_name
                    .try_extend_from_slice(name)
                    .and_then(|()| c_name.try_push(0))
                    .map_err(|OutOfMemory| DumpFailed::OutOfMemory)?;
                let c_name = Stream::c_name(&c_name);
                let keep = if fresh {
                    Keep::Nothing
                } else {
                    Keep::Everything
                };
                match fs::open_write(c_name, keep, NEW_FILE_MODE) {
                    Ok(file) => DumpTarget::File(Stdio::new(file)),
                    Err(_) => {
                        stream.msgs.error(&[b"Failed to open ", name]);
                        return Err(DumpFailed::Open);
                    }
                }
            }
        };
        stream.dump = Some(Dump {
            target,
            name: owned,
        });
        Ok(())
    }

    /// The write handler.
    pub(crate) fn body_handler(&self) -> Result<Handler<dyn WriteHandler>, OutOfMemory> {
        Handler::write(Body(self.clone()))
    }

    /// The header handler.
    pub(crate) fn header_handler(&self) -> Result<Handler<dyn HeaderHandler>, OutOfMemory> {
        Handler::header(Headers(self.clone()))
    }
}

/// The most names tried for a file not to clobber (`MAX_CLOBBER_ATTEMPTS`).
const MAX_CLOBBER: u32 = 9999;

/// `name`, a file name ended by a zero byte, opened only if nothing has
/// it, or else the first of its numbered names that nothing has, which
/// `name` then becomes (`tool_create_output_file`). The error is the last
/// name's, and that name is left in `tried`.
fn open_unclobbered(name: &mut Vec<u8>, tried: &mut Option<Vec<u8>>) -> std::io::Result<File> {
    let first = fs::open_write(Stream::c_name(name), Keep::Absent, NEW_FILE_MODE);
    let mut err = match first {
        Ok(f) => return Ok(f),
        Err(e) => e,
    };
    #[cfg_attr(not(feature = "debug-hooks"), expect(unused_mut))]
    let mut max = MAX_CLOBBER;
    // The debug test build takes the limit from `CURL_MAX_CLOBBER`.
    #[cfg(feature = "debug-hooks")]
    if let Some(n) = curl_os::env::var_into(b"CURL_MAX_CLOBBER", &mut [0u8; 32])
        .map(<std::ffi::OsStr as std::os::unix::ffi::OsStrExt>::from_bytes)
        .and_then(crate::memlimit)
        .filter(|&n| n <= 100_000)
    {
        max = n as u32;
    }
    let base = &name[..name.len() - 1];
    let mut next = 1;
    while matches!(
        err.kind(),
        std::io::ErrorKind::AlreadyExists | std::io::ErrorKind::IsADirectory
    ) && next < max
    {
        let numbered = clobber_name(base, next).map_err(|OutOfMemory| err_oom())?;
        next += 1;
        match fs::open_write(Stream::c_name(&numbered), Keep::Absent, NEW_FILE_MODE) {
            Ok(f) => {
                *name = numbered;
                return Ok(f);
            }
            Err(e) => {
                err = e;
                *tried = Some(numbered);
            }
        }
    }
    Err(err)
}

fn err_oom() -> std::io::Error {
    std::io::Error::from(std::io::ErrorKind::OutOfMemory)
}

/// `name` numbered `n`, ended by a zero byte: before its extension if its
/// base name has one, after it if not (`clobber_name`).
fn clobber_name(name: &[u8], n: u32) -> Result<Vec<u8>, OutOfMemory> {
    let base = name.iter().rposition(|&b| b == b'/').map_or(0, |i| i + 1);
    let dot = name[base..]
        .iter()
        .rposition(|&b| b == b'.')
        .map(|i| base + i);
    let mut out = Vec::new();
    match dot {
        Some(dot) if dot != base && dot + 1 < name.len() => {
            out.try_extend_from_slice(&name[..dot])?;
            push_number(&mut out, b'-', n)?;
            out.try_extend_from_slice(&name[dot..])?;
        }
        _ => {
            out.try_extend_from_slice(name)?;
            push_number(&mut out, b'.', n)?;
        }
    }
    out.try_push(0)?;
    Ok(out)
}

/// `sep` and `n` in decimal, after what `out` holds.
fn push_number(out: &mut Vec<u8>, sep: u8, n: u32) -> Result<(), OutOfMemory> {
    out.try_push(sep)?;
    let mut digits = [0u8; 10];
    let mut cursor = std::io::Cursor::new(&mut digits[..]);
    write!(cursor, "{n}").expect("a u32 fits in ten digits");
    let len = cursor.position() as usize;
    out.try_extend_from_slice(&digits[..len])
}

impl Stream {
    /// Header lines with a colon in the last response's head.
    pub(crate) fn num_headers(&self) -> u64 {
        self.num_headers
    }

    /// The output file's name, if the output is a file.
    pub(crate) fn file_name(&self) -> Option<&[u8]> {
        match &self.target {
            Target::File { name, .. } => Some(&name[..name.len() - 1]),
            Target::Stdout(_) | Target::Null => None,
        }
    }

    fn c_name(name: &[u8]) -> &CStr {
        CStr::from_bytes_with_nul(name).expect("a file name, ended by a zero byte")
    }

    /// Open the output file to add to what it holds, for a resumed
    /// download. C reports the failure itself (`setup_outfile`).
    pub(crate) fn open_to_append(&mut self) -> bool {
        let Target::File { name, file } = &mut self.target else {
            unreachable!("only a file is resumed");
        };
        match fs::open_write(Stream::c_name(name), Keep::Everything, NEW_FILE_MODE) {
            Ok(f) => {
                // C takes the size it was told to resume from; it is the
                // file's, read just before.
                self.init = f.metadata().map_or(0, |m| m.len());
                *file = Some(Stdio::new(f));
                true
            }
            Err(_) => {
                let shown = &name[..name.len() - 1];
                self.msgs.error(&[b"cannot open '", shown, b"'"]);
                false
            }
        }
    }

    /// Create the output file, emptied, if it is one not open yet
    /// (`tool_create_output_file`).
    pub(crate) fn create(&mut self) -> bool {
        let Target::File { name, file } = &mut self.target else {
            return true;
        };
        if file.is_some() {
            return true;
        }
        let mut tried = None;
        let opened = match self.clobber {
            Clobber::Never => open_unclobbered(name, &mut tried),
            // A name the server gives does not replace a file.
            Clobber::Default if self.server_named => {
                fs::open_write(Stream::c_name(name), Keep::Absent, NEW_FILE_MODE)
            }
            Clobber::Default | Clobber::Always => {
                fs::open_write(Stream::c_name(name), Keep::Nothing, NEW_FILE_MODE)
            }
        };
        match opened {
            Ok(f) => {
                *file = Some(Stdio::new(f));
                self.bytes = 0;
                self.init = 0;
                true
            }
            Err(e) => {
                let shown = &name[..name.len() - 1];
                let reason = os_message(&e);
                self.msgs
                    .warn(&[b"Failed to open the file ", shown, b": ", reason.as_bytes()]);
                // C's output is then named as the last name it tried,
                // though nothing was opened as it.
                if let Some(last) = tried {
                    *name = last;
                }
                false
            }
        }
    }

    /// Bytes written since the file was opened or last kept.
    pub(crate) fn written(&self) -> u64 {
        self.bytes
    }

    /// Where the bytes written start in the file.
    pub(crate) fn start(&self) -> u64 {
        self.init
    }

    /// The output is a file, open (`outs->fopened && outs->stream`).
    pub(crate) fn is_open_file(&self) -> bool {
        matches!(self.target, Target::File { file: Some(_), .. })
    }

    /// Keep what was written, for the next attempt to add to: where that
    /// one starts. `None` past the largest size C can hold.
    pub(crate) fn keep(&mut self) -> Option<u64> {
        let end = self
            .init
            .checked_add(self.bytes)
            .filter(|&e| e < i64::MAX as u64)?;
        self.init = end;
        self.bytes = 0;
        Some(end)
    }

    /// Drop what was written to a regular file, for the next attempt to
    /// write again (`retrycheck`). Standard output and what cannot be
    /// truncated keep it. False if the file could not be truncated; said
    /// already.
    pub(crate) fn throw_away(&mut self) -> bool {
        let Target::File {
            file: Some(file), ..
        } = &mut self.target
        else {
            return true;
        };
        if self.bytes == 0 || !file.get_ref().metadata().is_ok_and(|m| m.is_file()) {
            return true;
        }
        // Unchecked, as in C: a failure shows in the truncation.
        let _ = file.flush();
        if let Ok(n) = curl_alloc::try_format(format_args!("{}", self.bytes)) {
            self.msgs
                .note(&[b"Throwing away ", n.as_bytes(), b" bytes"]);
        }
        // The debug test build fails it on request.
        let fail = cfg!(feature = "debug-hooks") && curl_os::env::is_set(b"CURL_DBG_TRUNCATE_FAIL");
        if fail || file.get_ref().set_len(self.init).is_err() {
            self.msgs.error(&[b"Failed to truncate file"]);
            return false;
        }
        // Written on from where it now ends.
        if std::io::Seek::seek(file.get_mut(), std::io::SeekFrom::End(0)).is_err() {
            self.msgs.error(&[b"Failed seeking to end of file"]);
            return false;
        }
        self.bytes = 0;
        true
    }

    /// Write `bytes` through the stream's buffer: how many were taken
    /// (`fwrite`).
    fn fwrite(&mut self, bytes: &[u8]) -> usize {
        match &mut self.target {
            Target::Stdout(out) => out.fwrite(bytes),
            Target::Null => bytes.len(),
            Target::File { file, .. } => {
                file.as_mut().expect("created before writing").fwrite(bytes)
            }
        }
    }

    fn write_all(&mut self, bytes: &[u8]) -> std::io::Result<()> {
        if self.fwrite(bytes) == bytes.len() {
            Ok(())
        } else {
            Err(std::io::Error::from(std::io::ErrorKind::WriteZero))
        }
    }

    /// Write what the stream holds, if it is open (`fflush`).
    pub(crate) fn flush(&mut self) -> Result<(), stdio::Failed> {
        match &mut self.target {
            Target::Stdout(out) => out.flush(),
            Target::File {
                file: Some(file), ..
            } => file.flush(),
            Target::Null | Target::File { file: None, .. } => Ok(()),
        }
    }

    /// The output is standard output (`!outs->regular_file`).
    pub(crate) fn to_stdout(&self) -> bool {
        matches!(self.target, Target::Stdout(_))
    }

    /// A write to the open stream failed (`ferror`).
    pub(crate) fn failed(&self) -> bool {
        matches!(&self.target, Target::File { file: Some(file), .. } if file.failed())
    }

    /// Close the output file, if one is open (`fclose`): whether what it
    /// held could be written.
    pub(crate) fn close(&mut self) -> Result<(), stdio::Failed> {
        match &mut self.target {
            Target::File { file, .. } => file.take().map_or(Ok(()), stdio::close),
            Target::Stdout(_) | Target::Null => Ok(()),
        }
    }

    /// `tool_write_cb`.
    pub(crate) fn body(&mut self, body: &[u8]) -> Write {
        if matches!(self.target, Target::Null) {
            return Write::Accepted;
        }
        if !self.create() {
            return Write::Fail;
        }
        if self.terminal && self.bytes < BINARY_CHECK && !self.binary_ok && body.contains(&0) {
            self.msgs.warn(&[
                b"Binary output can mess up your terminal. Use \"--output -\" to tell curl to \
                  output it to your terminal anyway, or consider \"--output <FILE>\" to save \
                  to a file.",
            ]);
            return Write::Fail;
        }
        if self.write_held().is_err() {
            return Write::Fail;
        }
        let took = self.fwrite(body);
        if took == body.len() {
            self.bytes += body.len() as u64;
        }
        // `--no-buffer` writes it out now.
        if self.no_buffer && self.flush().is_err() {
            return Write::Fail;
        }
        if took == body.len() {
            Write::Accepted
        } else {
            Write::Took(took)
        }
    }

    /// The `--dump-header` side of `tool_header_cb`: every line, flushed.
    fn dump(&mut self, line: &[u8]) -> Write {
        let Some(dump) = &mut self.dump else {
            return Write::Accepted;
        };
        // A line not all taken is a count for the library to report.
        let took = dump.target.fwrite(line);
        if took < line.len() {
            return Write::Took(took);
        }
        match dump.target.flush() {
            Ok(()) => Write::Accepted,
            Err(stdio::Failed) => {
                self.msgs
                    .error(&[b"Failed writing headers to ", &dump.name]);
                Write::Fail
            }
        }
    }

    /// The output side of `tool_header_cb`: shown header lines, their
    /// names in bold on a terminal, of a response to the transfer's URL
    /// `url`.
    fn header(
        &mut self,
        line: &[u8],
        protocol: Option<Protocol>,
        code: Option<u16>,
        url: Option<&[u8]>,
    ) -> Write {
        if self.after_blank {
            self.num_headers = 0;
        }
        self.after_blank = matches!(line.first(), Some(b'\r' | b'\n'));
        if line.contains(&b':') {
            self.num_headers += 1;
        }
        let dumped = self.dump(line);
        if dumped != Write::Accepted {
            return dumped;
        }
        // A name is taken from a 2xx or 3xx response only.
        let http = protocol == Some(Protocol::Http);
        let mut named = false;
        if http && self.name_from_header.is_some() && code.is_some_and(|c| matches!(c / 100, 2 | 3))
        {
            match self.name_from(line, code.unwrap_or(0)) {
                Naming::Held => return Write::Accepted,
                Naming::Failed => return Write::Fail,
                Naming::Shown => named = true,
            }
        }
        // C shows them for HTTP, HTTPS, RTSP and FILE.
        if !self.show_headers || !matches!(protocol, Some(Protocol::File | Protocol::Http)) {
            return Write::Accepted;
        }
        // An interim response's lines wait for the name too.
        if http && !named && self.name_from_header.is_some() {
            return match self.hold(line) {
                Ok(()) => Write::Accepted,
                Err(OutOfMemory) => Write::Fail,
            };
        }
        if !self.create() {
            return Write::Fail;
        }
        let colon = line.iter().position(|&b| b == b':').filter(|_| self.styled);
        // C does not check these writes: a failure shows when the output
        // is next written, flushed or closed.
        match colon {
            Some(at) => {
                let (name, value) = (&line[..at], &line[at + 1..]);
                for part in [BOLD, name, BOLD_OFF, b":"] {
                    self.fwrite(part);
                }
                if names_location(name) {
                    self.linked_location(value, url);
                } else {
                    self.fwrite(value);
                }
            }
            None => {
                self.fwrite(line);
            }
        }
        Write::Accepted
    }
}

impl Stream {
    /// A `Location:` line's `value`, after its colon, made a link to the
    /// URL it leads to from `url`, where that is HTTP or FTP, with or
    /// without TLS (`write_linked_location`). The link starts after the
    /// leading blanks and ends after the line's end.
    fn linked_location(&mut self, value: &[u8], url: Option<&[u8]>) {
        let skipped = value
            .iter()
            .take_while(|&&b| b == b' ' || b == b'\t')
            .count();
        let mut buf = [0u8; 64];
        let vte = curl_os::env::var_into(b"VTE_VERSION", &mut buf);
        match url.and_then(|url| link_target(&value[skipped..], url, vte)) {
            Some(target) => {
                for part in [
                    &value[..skipped],
                    LINK,
                    &target,
                    LINK_END,
                    &value[skipped..],
                    LINK,
                    LINK_END,
                ] {
                    self.fwrite(part);
                }
            }
            None => {
                self.fwrite(value);
            }
        }
    }

    /// The `--remote-header-name` side of `tool_header_cb`
    /// (`content_disposition`): a 3xx's `Location:` names the file for
    /// now; `Content-Disposition:` names it for good with its `filename=`,
    /// and has it made, with the lines held written to it.
    fn name_from(&mut self, line: &[u8], code: u16) -> Naming {
        let starts = |prefix: &[u8]| {
            line.len() > prefix.len() && line[..prefix.len()].eq_ignore_ascii_case(prefix)
        };
        if starts(b"Location:") && code / 100 == 3 {
            let at = 9 + blanks(&line[9..]);
            if at < line.len()
                && let Some(name) = file_name_in(&line[at..], None)
                && !self.rename(name)
            {
                return Naming::Failed;
            }
        } else if starts(b"Content-disposition:") {
            match self.disposition(line) {
                Ok(true) => {}
                Ok(false) | Err(OutOfMemory) => return Naming::Failed,
            }
        }
        if self.name_from_header.is_some() && self.show_headers {
            return match self.hold(line) {
                Ok(()) => Naming::Held,
                Err(OutOfMemory) => Naming::Failed,
            };
        }
        Naming::Shown
    }

    /// The `filename=` of a `Content-Disposition:` line, if it has one
    /// that names a file (encoded ones, `filename*=`, are not read); the
    /// file is made either way. Whether all went well.
    fn disposition(&mut self, line: &[u8]) -> Result<bool, OutOfMemory> {
        let mut at = 20;
        loop {
            while at < line.len() && line[at] != 0 && !line[at].is_ascii_alphabetic() {
                at += 1;
            }
            if at + 9 > line.len() {
                break;
            }
            if &line[at..at + 9] != b"filename=" {
                // Not it: the next parameter.
                while at < line.len() && line[at] != 0 && line[at] != b';' {
                    at += 1;
                }
                if at < line.len() && line[at] != 0 {
                    continue;
                }
                break;
            }
            at += 9;
            at += blanks(&line[at..]);
            if let Some(name) = file_name_in(&line[at..], Some(b';')) {
                if !self.rename(name) {
                    return Ok(false);
                }
                // Named for good: what follows is shown as it comes.
                let held = self.name_from_header.take().map(|f| f.held);
                if !self.create() || self.write_lines(held.as_deref().unwrap_or(&[])).is_err() {
                    return Ok(false);
                }
            }
            break;
        }
        Ok(self.create() && self.write_held().is_ok())
    }

    /// Name the file `name`, in the output directory if one is given,
    /// as the server says (`set_filename`); not once it is open.
    fn rename(&mut self, name: Vec<u8>) -> bool {
        let dir = self
            .name_from_header
            .as_ref()
            .and_then(|f| f.dir.as_deref());
        let Target::File {
            name: current,
            file,
        } = &mut self.target
        else {
            return false;
        };
        if file.is_some() {
            return false;
        }
        let mut full = Vec::new();
        let made = (|| {
            if let Some(dir) = dir {
                full.try_extend_from_slice(dir)?;
                full.try_push(b'/')?;
            }
            full.try_extend_from_slice(&name)?;
            full.try_push(0)
        })();
        if made.is_err() {
            return false;
        }
        *current = full;
        self.server_named = true;
        true
    }

    /// Hold `line` until the file is named (`buffer_header`).
    fn hold(&mut self, line: &[u8]) -> Result<(), OutOfMemory> {
        let from = self
            .name_from_header
            .as_mut()
            .expect("held only while unnamed");
        let mut copy = Vec::new();
        copy.try_extend_from_slice(line)?;
        from.held.try_push(copy)
    }

    /// Write the lines held, as they came, and forget them
    /// (`tool_write_headers`).
    fn write_held(&mut self) -> std::io::Result<()> {
        let held = match &mut self.name_from_header {
            Some(from) => std::mem::take(&mut from.held),
            None => return Ok(()),
        };
        self.write_lines(&held)
    }

    fn write_lines(&mut self, lines: &[Vec<u8>]) -> std::io::Result<()> {
        lines.iter().try_for_each(|line| self.write_all(line))
    }
}

/// Write `bytes` to `to` straight through until done or a write fails:
/// how many were written, as `fwrite` counts on an unbuffered stream.
fn unbuffered(to: &mut impl std::io::Write, bytes: &[u8]) -> usize {
    let mut at = 0;
    while at < bytes.len() {
        match to.write(&bytes[at..]) {
            Ok(0) | Err(_) => break,
            Ok(n) => at += n,
        }
    }
    at
}

/// `s` up to the first `at` in it.
fn cut(s: &[u8], at: u8) -> &[u8] {
    match s.iter().position(|&b| b == at) {
        Some(end) => &s[..end],
        None => s,
    }
}

/// How many blanks `s` starts with.
fn blanks(s: &[u8]) -> usize {
    s.iter().take_while(|&&b| b == b' ' || b == b'\t').count()
}

/// The file name in `value`, the rest of a header line (`parse_filename`):
/// up to `stop`, or the quote it starts with, for `Content-Disposition`;
/// without a query or fragment for `Location`. Only the part after the
/// last slash or backslash is kept, up to a line end. Nothing, `.` or
/// `..` names no file.
fn file_name_in(value: &[u8], stop: Option<u8>) -> Option<Vec<u8>> {
    // C reads it as a string.
    let mut s = &value[..value.iter().position(|&b| b == 0).unwrap_or(value.len())];
    match stop {
        Some(mut stop) => {
            if let Some(&quote @ (b'\'' | b'"')) = s.first() {
                stop = quote;
                s = &s[1..];
            }
            s = cut(s, stop);
        }
        None => s = cut(cut(s, b'?'), b'#'),
    }
    for separator in *b"/\\" {
        if let Some(at) = s.iter().rposition(|&b| b == separator) {
            s = &s[at + 1..];
        }
    }
    s = cut(cut(s, b'\r'), b'\n');
    if s.is_empty() || s == b"." || s == b".." {
        return None;
    }
    let mut name = Vec::new();
    name.try_extend_from_slice(s).ok()?;
    Some(name)
}

/// `--stderr`: from now on standard error goes to the file `name`,
/// emptied, or to standard output for `-` (`tool_set_stderr_file`). A file
/// that cannot be opened is warned of, and standard error stays.
pub(crate) fn redirect_stderr(name: &[u8], msgs: &Messages) {
    let moved = if name == b"-" {
        fs::stderr_to(&std::io::stdout())
    } else {
        fs::with_c_name(name, |c| fs::open_write(c, Keep::Nothing, NEW_FILE_MODE))
            .and_then(|file| fs::stderr_to(&file))
    };
    if moved.is_err() {
        // C's text, with its prefix twice.
        msgs.warn(&[b"Warning: Failed to open ", name]);
    }
}

struct Body(Output);

impl WriteHandler for Body {
    fn write(&self, _: &mut TransferCx<'_>, body: &[u8]) -> Write {
        self.0.stream().body(body)
    }
}

struct Headers(Output);

impl HeaderHandler for Headers {
    fn header(&self, cx: &mut TransferCx<'_>, line: &[u8], _: HeaderOrigin) -> Write {
        let report = cx.info(cx.me());
        let protocol = report.and_then(|r| r.protocol());
        let code = report.and_then(|r| r.response_code());
        let url = report.and_then(|r| r.url());
        self.0.stream().header(line, protocol, code, url)
    }
}

/// Whether a header `name` is taken for `Location`, as `curl_strnequal`
/// compares them: a shorter name that starts it is.
fn names_location(name: &[u8]) -> bool {
    let location = b"Location";
    name.len() <= location.len() && name.eq_ignore_ascii_case(&location[..name.len()])
}

/// What a `Location:` links to, `location` without its leading blanks
/// resolved against `url`, or nothing to link: a terminal that may show
/// links badly, its `VTE_VERSION` given as `vte`, a URL that does not
/// resolve, or one whose scheme is not HTTP or FTP, with or without TLS.
fn link_target(location: &[u8], url: &[u8], vte: Option<&[u8]>) -> Option<Vec<u8>> {
    // VTE 0.48.1 and older show some links badly.
    if let Some(version) = vte {
        let digits = version.iter().take_while(|b| b.is_ascii_digit()).count();
        let number = std::str::from_utf8(&version[..digits])
            .ok()
            .and_then(|d| d.parse::<i64>().ok());
        if number.is_none_or(|n| n <= 4801) {
            return None;
        }
    }
    let end = location
        .iter()
        .rposition(|&b| b != b'\r' && b != b'\n')
        .map_or(0, |at| at + 1);
    // C copies it as a string: it ends at a zero byte.
    let location = location[..end]
        .split(|&b| b == 0)
        .next()
        .unwrap_or_default();
    let mut parsed = Url::parse(url, ParseOptions::NONE).ok()?;
    parsed
        .set(Part::Url, Some(location), SetOptions::NONE)
        .ok()?;
    let target = parsed
        .get(
            Part::Url,
            GetOptions {
                no_default_port: true,
                ..GetOptions::NONE
            },
        )
        .ok()?;
    let scheme = parsed.get(Part::Scheme, GetOptions::NONE).ok()?;
    matches!(&scheme[..], b"http" | b"https" | b"ftp" | b"ftps").then_some(target)
}

#[cfg(test)]
mod tests {

    use super::*;

    /// A number goes before an extension, or after a name without one;
    /// a leading dot or a trailing one is no extension.
    #[test]
    fn clobber_names_number_as_c_does() {
        let name = |n: &str, i| String::from_utf8(clobber_name(n.as_bytes(), i).unwrap()).unwrap();
        assert_eq!(name("a/b.txt", 1), "a/b-1.txt\0");
        assert_eq!(name("a.d/b", 2), "a.d/b.2\0");
        assert_eq!(name("a/.hidden", 3), "a/.hidden.3\0");
        assert_eq!(name("b.", 4), "b..4\0");
        assert_eq!(name("x.tar.gz", 12), "x.tar-12.gz\0");
    }

    fn quiet() -> Messages {
        let mut msgs = Messages::new();
        msgs.silent = true;
        msgs
    }

    fn to_terminal() -> Output {
        let out = Output::file(b"/dev/null", quiet()).unwrap();
        out.stream().terminal = true;
        out
    }

    /// The header count is the last response's lines with a colon,
    /// whether shown or not: an interim response's are forgotten.
    #[test]
    fn counts_the_last_responses_header_lines() {
        let out = Output::null(quiet()).unwrap();
        let mut s = out.stream();
        let lines: [&[u8]; 7] = [
            b"HTTP/1.1 100 Continue\r\n",
            b"A: 1\r\n",
            b"\r\n",
            b"HTTP/1.1 200 OK\r\n",
            b"B: 2\r\n",
            b"C: 3\r\n",
            b"\r\n",
        ];
        for line in lines {
            assert_eq!(
                s.header(line, Some(Protocol::Http), Some(200), None),
                Write::Accepted
            );
        }
        assert_eq!(s.num_headers(), 2);
    }

    /// Binary output to a terminal is refused in its first 2000 bytes,
    /// unless `--output -` asks for it.
    #[test]
    fn refuses_binary_at_the_start_of_a_terminal() {
        let out = to_terminal();
        let mut s = out.stream();
        assert_eq!(s.body(b"text"), Write::Accepted);
        assert_eq!(s.body(b"a\0b"), Write::Fail);
        let out = to_terminal();
        let mut s = out.stream();
        assert_eq!(s.body(&[b'a'; 1999]), Write::Accepted);
        assert_eq!(s.body(b"\0"), Write::Fail);
        let out = to_terminal();
        let mut s = out.stream();
        assert_eq!(s.body(&[b'a'; 1000]), Write::Accepted);
        assert_eq!(s.body(&[b'a'; 1000]), Write::Accepted);
        assert_eq!(s.body(b"\0"), Write::Accepted);
        let out = to_terminal();
        let mut s = out.stream();
        s.binary_ok = true;
        assert_eq!(s.body(b"\0"), Write::Accepted);
        let out = Output::null(quiet()).unwrap();
        assert_eq!(out.stream().body(b"\0"), Write::Accepted);
    }

    /// `parse_filename`: the last part of a path, up to the stop or the
    /// quote it starts with, without a URL's query; `.` and `..` are no
    /// names.
    #[test]
    fn reads_a_file_name_as_c_does() {
        let name =
            |v: &str, stop| file_name_in(v.as_bytes(), stop).map(|n| String::from_utf8(n).unwrap());
        let cd = Some(b';');
        assert_eq!(name("\"a/b.txt\"; x\r\n", cd).as_deref(), Some("b.txt"));
        assert_eq!(name("'x;y'\r\n", cd).as_deref(), Some("x;y"));
        assert_eq!(name("n.txt; size=3\r\n", cd).as_deref(), Some("n.txt"));
        assert_eq!(name("c:\\dos\\f\r\n", cd).as_deref(), Some("f"));
        assert_eq!(
            name("/dir/f.html?q=/a#x\r\n", None).as_deref(),
            Some("f.html")
        );
        assert_eq!(name("..\r\n", cd), None);
        assert_eq!(name("\"\"\r\n", cd), None);
    }

    /// With `--remote-header-name`, the lines to show wait for the name,
    /// a 3xx's `Location:` names the file for now and
    /// `Content-Disposition:` for good; a file there is not replaced.
    #[test]
    fn names_the_file_from_the_response() {
        let dir = scratch("cd");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("url-name");
        let out = Output::file(path.as_os_str().as_encoded_bytes(), quiet()).unwrap();
        {
            let mut s = out.stream();
            s.show_headers = true;
            s.name_from_header =
                Some(FromHeader::new(Some(dir.as_os_str().as_encoded_bytes())).unwrap());
        }
        let http = Some(Protocol::Http);
        let lines: [(&[u8], u16); 5] = [
            (b"HTTP/1.1 301 Moved\r\n", 301),
            (b"Location: /a/moved?x\r\n", 301),
            (b"\r\n", 301),
            (b"HTTP/1.1 200 OK\r\n", 200),
            (b"Content-Disposition: inline; filename=\"final\"\r\n", 200),
        ];
        for (line, code) in lines {
            assert_eq!(
                out.stream().header(line, http, Some(code), None),
                Write::Accepted
            );
        }
        assert_eq!(
            out.stream().header(b"\r\n", http, Some(200), None),
            Write::Accepted
        );
        assert_eq!(out.stream().body(b"body"), Write::Accepted);
        let final_path = dir.join("final");
        assert_eq!(
            out.stream().file_name(),
            Some(final_path.as_os_str().as_encoded_bytes())
        );
        drop(out);
        let written = std::fs::read(&final_path).unwrap();
        assert_eq!(
            written,
            b"HTTP/1.1 301 Moved\r\nLocation: /a/moved?x\r\n\r\nHTTP/1.1 200 OK\r\n\
              Content-Disposition: inline; filename=\"final\"\r\n\r\nbody"
        );
        assert!(!dir.join("moved").exists() && !path.exists());
        // A second time the name is taken: the file stays.
        let out = Output::file(path.as_os_str().as_encoded_bytes(), quiet()).unwrap();
        out.stream().name_from_header =
            Some(FromHeader::new(Some(dir.as_os_str().as_encoded_bytes())).unwrap());
        let line = b"Content-Disposition: inline; filename=final\r\n";
        assert_eq!(
            out.stream().header(line, http, Some(200), None),
            Write::Fail
        );
        assert_eq!(std::fs::read(&final_path).unwrap(), written);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// What an attempt wrote is thrown away back to where the file was
    /// opened, and the next attempt written after it; or kept, the next
    /// added to it (`retrycheck`).
    #[test]
    fn throws_away_or_keeps_what_an_attempt_wrote() {
        let path = scratch("retried");
        std::fs::write(&path, b"held").unwrap();
        let out = Output::file(path.as_os_str().as_encoded_bytes(), quiet()).unwrap();
        let mut s = out.stream();
        assert!(s.open_to_append());
        assert_eq!(s.start(), 4);
        assert_eq!(s.body(b"first"), Write::Accepted);
        assert_eq!(s.written(), 5);
        assert!(s.throw_away());
        assert_eq!(s.written(), 0);
        assert_eq!(std::fs::read(&path).unwrap(), b"held");
        assert_eq!(s.body(b"again"), Write::Accepted);
        assert_eq!(s.keep(), Some(9));
        assert_eq!((s.start(), s.written()), (9, 0));
        assert_eq!(s.body(b"+more"), Write::Accepted);
        // Written once flushed, as stdio holds it until then.
        assert_eq!(std::fs::read(&path).unwrap(), b"held");
        assert_eq!(s.flush(), Ok(()));
        assert_eq!(std::fs::read(&path).unwrap(), b"heldagain+more");
        // A file created empty starts at 0, and is written from where it
        // was cut, not where the last write left off.
        drop(s);
        let path = scratch("retried-new");
        let out = Output::file(path.as_os_str().as_encoded_bytes(), quiet()).unwrap();
        let mut s = out.stream();
        assert_eq!(s.body(b"partial"), Write::Accepted);
        assert!(s.throw_away());
        assert_eq!(s.body(b"all"), Write::Accepted);
        assert_eq!(s.flush(), Ok(()));
        assert_eq!(std::fs::read(&path).unwrap(), b"all");
    }

    /// What is kept may end only before C's largest offset.
    #[test]
    fn keeps_up_to_the_largest_offset() {
        let out = Output::null(quiet()).unwrap();
        let mut s = out.stream();
        let max = i64::MAX as u64;
        (s.init, s.bytes) = (max - 5, 4);
        assert_eq!(s.keep(), Some(max - 1));
        (s.init, s.bytes) = (max - 5, 5);
        assert_eq!(s.keep(), None);
    }

    /// Only a regular file has what an attempt wrote thrown away: a
    /// device keeps it.
    #[test]
    fn throws_away_only_from_a_regular_file() {
        let out = Output::file(b"/dev/null", quiet()).unwrap();
        let mut s = out.stream();
        assert_eq!(s.body(b"abc"), Write::Accepted);
        assert!(s.throw_away());
        assert_eq!(s.written(), 3);
    }

    fn scratch(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("curl-tool-output-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        dir.join(name)
    }

    /// What `--include` writes of `lines` from a protocol, styled for a
    /// terminal or not.
    fn shown(lines: &[&[u8]], protocol: Option<Protocol>, styled: bool) -> Vec<u8> {
        let path = scratch(&format!("{protocol:?}-{styled}"));
        let out = Output::file(path.as_os_str().as_encoded_bytes(), quiet()).unwrap();
        {
            let mut s = out.stream();
            s.show_headers = true;
            s.styled = styled;
            for line in lines {
                assert_eq!(s.header(line, protocol, None, None), Write::Accepted);
            }
            assert!(s.create());
        }
        drop(out);
        let shown = std::fs::read(&path).unwrap();
        std::fs::remove_file(&path).unwrap();
        shown
    }

    /// `--dump-header` writes every line, for any protocol and whether
    /// shown or not; its file is emptied by an operation's first transfer
    /// and added to by the rest.
    #[test]
    fn dumps_headers_to_a_file() {
        let path = scratch("dump");
        std::fs::write(&path, b"old\n").unwrap();
        let name = path.as_os_str().as_encoded_bytes();
        let stdout = Stdout::new().unwrap();
        for (fresh, line) in [(true, &b"A: 1\r\n"[..]), (false, b"B: 2\r\n")] {
            let out = Output::null(quiet()).unwrap();
            assert!(out.dump_to(name, fresh, &stdout).is_ok());
            assert_eq!(out.stream().header(line, None, None, None), Write::Accepted);
        }
        assert_eq!(std::fs::read(&path).unwrap(), b"A: 1\r\nB: 2\r\n");
        std::fs::remove_file(&path).unwrap();
        let out = Output::null(quiet()).unwrap();
        let missing = scratch("no/such/dir");
        assert!(matches!(
            out.dump_to(missing.as_os_str().as_encoded_bytes(), true, &stdout),
            Err(DumpFailed::Open)
        ));
    }

    /// A header line too long for the buffer fails at once, its count
    /// for the library to report; one held fails as it is flushed.
    #[test]
    fn dumps_headers_short_to_a_full_device() {
        let stdout = Stdout::new().unwrap();
        let out = Output::null(quiet()).unwrap();
        assert!(out.dump_to(b"/dev/full", true, &stdout).is_ok());
        let mut long = vec![b'x'; 16384];
        long.extend_from_slice(b": y\r\n");
        assert_eq!(out.stream().header(&long, None, None, None), Write::Took(0));
        assert_eq!(
            out.stream().header(b"A: 1\r\n", None, None, None),
            Write::Fail
        );
    }

    /// A write to the output file that failed is remembered (`ferror`):
    /// what was written is then not resumed from.
    #[test]
    fn remembers_a_failed_write() {
        let out = Output::file(b"/dev/full", quiet()).unwrap();
        let mut s = out.stream();
        assert!(s.create());
        assert!(!s.failed());
        assert_eq!(s.body(&[b'x'; 16384]), Write::Took(0));
        assert!(s.failed());
        let out = Output::file(b"/dev/null", quiet()).unwrap();
        let mut s = out.stream();
        assert_eq!(s.body(&[b'x'; 16384]), Write::Accepted);
        assert!(!s.failed());
    }

    /// A `Location:` links to where it leads from the transfer's URL, in a
    /// terminal that shows links well, for HTTP and FTP only
    /// (`write_linked_location`).
    #[test]
    fn links_a_location_as_c_does() {
        let base = b"http://example.com:80/a/b";
        let link = |location: &str, vte: Option<&str>| {
            link_target(location.as_bytes(), base, vte.map(str::as_bytes))
                .map(|t| String::from_utf8(t).unwrap())
        };
        let here = Some("http://example.com/a/here".to_string());
        assert_eq!(link("here\r\n", None), here);
        assert_eq!(link("here\n\r\n", Some("4802")), here);
        assert_eq!(link("here\r\n", Some("4802x")), here);
        assert_eq!(link("here\r\n", Some("4801")), None);
        assert_eq!(link("here\r\n", Some("")), None);
        assert_eq!(link("here\r\n", Some("99999999999999999999")), None);
        assert_eq!(
            link("/x\0y\r\n", None),
            Some("http://example.com/x".to_string())
        );
        assert_eq!(link("FTPS://h:990/f", None), Some("ftps://h/f".to_string()));
        assert_eq!(link("file:///etc/passwd", None), None);
        assert_eq!(link("http://[::1\r\n", None), None);
        assert!(names_location(b"location"));
        assert!(names_location(b"Loc"));
        assert!(names_location(b""));
        assert!(!names_location(b"Locations"));
        assert!(!names_location(b"Content-Location"));
    }

    /// Header names are bold on a terminal; lines without one are not.
    #[test]
    fn shows_header_names_in_bold_on_a_terminal() {
        let lines: [&[u8]; 3] = [b"Name: a:b\r\n", b"plain\r\n", b"\r\n"];
        assert_eq!(
            shown(&lines, Some(Protocol::File), true),
            b"\x1b[1mName\x1b[0m: a:b\r\nplain\r\n\r\n"
        );
        assert_eq!(
            shown(&lines, Some(Protocol::File), false),
            b"Name: a:b\r\nplain\r\n\r\n"
        );
        assert_eq!(shown(&lines, None, false), b"");
    }

    const WORDS: &[&[u8]] = &[
        b"Content-Disposition:",
        b"content-disposition: ",
        b"attachment",
        b"; ",
        b";",
        b"filename=",
        b"filename*=",
        b"name=",
        b"\"",
        b"'",
        b"a.txt",
        b"/",
        b"\\",
        b"..",
        b".",
        b"Location:",
        b"location: ",
        b"http://h/dir/f.html",
        b"?q",
        b"#f",
        b"\r\n",
        b"\n",
        b"\0",
        b" ",
        b"\t",
        b"HTTP/1.1 200 OK\r\n",
        b"\r\n",
    ];
    const LINES: &[&[u8]] = &[
        b"Content-Disposition: attachment; filename=\"a b.txt\"\r\n",
        b"content-disposition: inline; name=x; filename='/etc/../passwd';\r\n",
        b"Location: http://h/dir/name.html?x#y\r\n",
        b"Content-Disposition: filename=\\\\server\\share\\f\r\n",
    ];

    proptest::proptest! {
        #![proptest_config(crate::untrusted::config(512))]

        /// Any header lines are shown, held or refused as the output is
        /// named from them, for any response code; a name taken from a
        /// line names a file in the directory, never one above it.
        #[test]
        fn any_header_names_a_file_or_not(
            lines in proptest::collection::vec(crate::untrusted::input(WORDS, LINES, 8), 1..6),
            code in proptest::sample::select(&[200u16, 204, 301, 302, 404][..]),
            show in proptest::prelude::any::<bool>(),
        ) {
            for line in &lines {
                for stop in [Some(b';'), None] {
                    if let Some(name) = file_name_in(line, stop) {
                        proptest::prop_assert!(!name.is_empty() && name != b"." && name != b"..");
                        proptest::prop_assert!(!name.iter().any(|b| matches!(b, b'/' | b'\\')));
                    }
                }
            }
            let out = Output::null(quiet()).unwrap();
            let mut s = out.stream();
            s.name_from_header = Some(FromHeader::new(Some(b"dir")).unwrap());
            s.show_headers = show;
            for line in &lines {
                s.header(line, Some(Protocol::Http), Some(code), None);
            }
        }
    }
}
