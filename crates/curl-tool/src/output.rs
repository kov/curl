//! Where a transfer's body and shown headers go: standard output, nowhere,
//! or a file, created when the first byte comes (`src/tool_cb_wrt.c`, and
//! the output side of `src/tool_cb_hdr.c`).

use core::ffi::CStr;
use std::cell::RefCell;
use std::fs::File;
use std::io::Write as _;

use curl_alloc::{OutOfMemory, TryRc, TryVec};
use curl_core::handler::{Handler, HeaderHandler, HeaderOrigin, Write, WriteHandler};
use curl_core::multi::TransferCx;
use curl_core::version::Protocol;
use curl_os::fs::{self, Keep};

use crate::msgs::Messages;
use crate::os_message;
use crate::stdout::Stdout;

/// What `fopen` creates a file with, before the umask.
const NEW_FILE_MODE: u32 = 0o666;

/// C's limit on binary bytes checked for, at the start of the output.
const BINARY_CHECK: u64 = 2000;

/// Starts header names on a terminal.
const BOLD: &[u8] = b"\x1b[1m";
/// Ends them: every attribute off, as not every terminal knows bold off.
const BOLD_OFF: &[u8] = b"\x1b[0m";

/// A transfer's output, shared by its write and header handlers and the
/// code that runs the transfer.
#[derive(Clone)]
pub(crate) struct Output(TryRc<RefCell<Stream>>);

/// Where output goes, and how (C's `struct OutStruct`).
pub(crate) struct Stream {
    target: Target,
    /// Bytes written (`outs->bytes`).
    bytes: u64,
    /// Header lines are written too: `--include`.
    pub(crate) show_headers: bool,
    /// Standard output is a terminal: binary output is refused and header
    /// names are bold.
    pub(crate) terminal: bool,
    /// `--output -`: binary output to a terminal is wanted.
    pub(crate) binary_ok: bool,
    /// `--no-buffer`: what is written is flushed at once.
    pub(crate) no_buffer: bool,
    /// `--dump-header`: where header lines are written too.
    dump: Option<Dump>,
    /// Header lines with a colon in the last response's head
    /// (`per->num_headers`).
    num_headers: u64,
    /// The last header line was blank: the next starts a response.
    after_blank: bool,
    msgs: Messages,
}

/// Where `--dump-header` writes, and the name it was given.
struct Dump {
    target: DumpTarget,
    name: Vec<u8>,
}

enum DumpTarget {
    Stdout(Stdout),
    Stderr,
    File(File),
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
    /// A file, by name with a zero byte after it; opened when needed.
    File {
        name: Vec<u8>,
        file: Option<File>,
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
            show_headers: false,
            terminal: false,
            binary_ok: false,
            no_buffer: false,
            dump: None,
            num_headers: 0,
            after_blank: true,
            msgs,
        };
        Ok(Output(TryRc::try_new(RefCell::new(stream))?))
    }

    pub(crate) fn stream(&self) -> std::cell::RefMut<'_, Stream> {
        self.0.borrow_mut()
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
                    Ok(file) => DumpTarget::File(file),
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
                *file = Some(f);
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
        match fs::open_write(Stream::c_name(name), Keep::Nothing, NEW_FILE_MODE) {
            Ok(f) => {
                *file = Some(f);
                self.bytes = 0;
                true
            }
            Err(e) => {
                let shown = &name[..name.len() - 1];
                let reason = os_message(&e);
                self.msgs
                    .warn(&[b"Failed to open the file ", shown, b": ", reason.as_bytes()]);
                false
            }
        }
    }

    fn write_all(&mut self, bytes: &[u8]) -> std::io::Result<()> {
        match &mut self.target {
            Target::Stdout(out) => out.write_all(bytes),
            Target::Null => Ok(()),
            Target::File { file, .. } => file
                .as_mut()
                .expect("created before writing")
                .write_all(bytes),
        }
    }

    /// Flush standard output; a file is written straight through.
    pub(crate) fn flush(&mut self) -> std::io::Result<()> {
        match &self.target {
            Target::Stdout(out) => out.flush(),
            Target::Null | Target::File { .. } => Ok(()),
        }
    }

    /// `tool_write_cb`.
    fn body(&mut self, body: &[u8]) -> Write {
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
        match self.write_all(body) {
            Ok(()) => {
                self.bytes += body.len() as u64;
                if self.no_buffer && self.flush().is_err() {
                    return Write::Fail;
                }
                Write::Accepted
            }
            Err(_) => Write::Fail,
        }
    }

    /// The `--dump-header` side of `tool_header_cb`: every line, flushed.
    fn dump(&mut self, line: &[u8]) -> Write {
        let Some(dump) = &mut self.dump else {
            return Write::Accepted;
        };
        let written = match &mut dump.target {
            DumpTarget::Stdout(out) => out.write_all(line).and_then(|()| out.flush()),
            DumpTarget::Stderr => {
                let mut err = std::io::stderr();
                err.write_all(line).and_then(|()| err.flush())
            }
            DumpTarget::File(file) => file.write_all(line),
        };
        match written {
            Ok(()) => Write::Accepted,
            Err(_) => {
                self.msgs
                    .error(&[b"Failed writing headers to ", &dump.name]);
                Write::Fail
            }
        }
    }

    /// The output side of `tool_header_cb`: shown header lines, their
    /// names in bold on a terminal.
    fn header(&mut self, line: &[u8], protocol: Option<Protocol>) -> Write {
        if self.after_blank {
            self.num_headers = 0;
        }
        self.after_blank = matches!(line.first(), Some(b'\r' | b'\n'));
        if line.contains(&b':') {
            self.num_headers += 1;
        }
        if self.dump(line) == Write::Fail {
            return Write::Fail;
        }
        // C shows them for HTTP, HTTPS, RTSP and FILE.
        if !self.show_headers || !matches!(protocol, Some(Protocol::File | Protocol::Http)) {
            return Write::Accepted;
        }
        if !self.create() {
            return Write::Fail;
        }
        let colon = line
            .iter()
            .position(|&b| b == b':')
            .filter(|_| self.terminal);
        let written = match colon {
            Some(at) => [BOLD, &line[..at], BOLD_OFF, b":", &line[at + 1..]]
                .into_iter()
                .try_for_each(|part| self.write_all(part)),
            None => self.write_all(line),
        };
        // C does not check these writes; here a failed one fails the
        // transfer, as a failed body write does.
        match written {
            Ok(()) => Write::Accepted,
            Err(_) => Write::Fail,
        }
    }
}

/// `--stderr`: from now on standard error goes to the file `name`,
/// emptied, or to standard output for `-` (`tool_set_stderr_file`). A file
/// that cannot be opened is warned of, and standard error stays.
pub(crate) fn redirect_stderr(name: &[u8], msgs: &Messages) {
    use std::os::unix::ffi::OsStrExt as _;
    let moved = if name == b"-" {
        fs::stderr_to(&std::io::stdout())
    } else {
        File::create(std::ffi::OsStr::from_bytes(name)).and_then(|file| fs::stderr_to(&file))
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
        let protocol = cx.info(cx.me()).and_then(|r| r.protocol());
        self.0.stream().header(line, protocol)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn quiet() -> Messages {
        let mut msgs = Messages::new();
        msgs.silent = true;
        msgs
    }

    fn to_terminal() -> Output {
        let out = Output::null(quiet()).unwrap();
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
            assert_eq!(s.header(line, Some(Protocol::Http)), Write::Accepted);
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

    fn scratch(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("curl-tool-output-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        dir.join(name)
    }

    /// What `--include` writes of `lines` from a protocol, to a terminal or
    /// not.
    fn shown(lines: &[&[u8]], protocol: Option<Protocol>, terminal: bool) -> Vec<u8> {
        let path = scratch(&format!("{protocol:?}-{terminal}"));
        let out = Output::file(path.as_os_str().as_encoded_bytes(), quiet()).unwrap();
        {
            let mut s = out.stream();
            s.show_headers = true;
            s.terminal = terminal;
            for line in lines {
                assert_eq!(s.header(line, protocol), Write::Accepted);
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
            assert_eq!(out.stream().header(line, None), Write::Accepted);
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
}
