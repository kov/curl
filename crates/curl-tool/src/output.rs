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
    msgs: Messages,
}

enum Target {
    Stdout,
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
    pub(crate) fn stdout(msgs: Messages) -> Result<Output, OutOfMemory> {
        Output::new(Target::Stdout, msgs)
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
            msgs,
        };
        Ok(Output(TryRc::try_new(RefCell::new(stream))?))
    }

    pub(crate) fn stream(&self) -> std::cell::RefMut<'_, Stream> {
        self.0.borrow_mut()
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
    /// The output file's name, if the output is a file.
    pub(crate) fn file_name(&self) -> Option<&[u8]> {
        match &self.target {
            Target::File { name, .. } => Some(&name[..name.len() - 1]),
            Target::Stdout | Target::Null => None,
        }
    }

    fn c_name(name: &[u8]) -> &CStr {
        CStr::from_bytes_with_nul(name).expect("a file name, ended by a zero byte")
    }

    pub(crate) fn is_null(&self) -> bool {
        matches!(self.target, Target::Null)
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
            Target::Stdout => std::io::stdout().lock().write_all(bytes),
            Target::Null => Ok(()),
            Target::File { file, .. } => file
                .as_mut()
                .expect("created before writing")
                .write_all(bytes),
        }
    }

    /// Flush standard output; a file is written straight through.
    pub(crate) fn flush(&mut self) -> std::io::Result<()> {
        match self.target {
            Target::Stdout => std::io::stdout().lock().flush(),
            Target::Null | Target::File { .. } => Ok(()),
        }
    }

    /// Close the output file, if one is open.
    pub(crate) fn close(&mut self) {
        if let Target::File { file, .. } = &mut self.target {
            // A `File` reports nothing on closing: what `fclose` would
            // have found unwritten was written, or failed, already.
            *file = None;
        }
    }

    /// `tool_write_cb`.
    fn body(&mut self, body: &[u8]) -> Write {
        if self.is_null() {
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
        match self.write_all(body) {
            Ok(()) => {
                self.bytes += body.len() as u64;
                Write::Accepted
            }
            Err(_) => Write::Fail,
        }
    }

    /// The output side of `tool_header_cb`: shown header lines, their
    /// names in bold on a terminal.
    fn header(&mut self, line: &[u8], protocol: Option<Protocol>) -> Write {
        // C shows them for HTTP, HTTPS, RTSP and FILE.
        if !self.show_headers || self.is_null() || protocol != Some(Protocol::File) {
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
