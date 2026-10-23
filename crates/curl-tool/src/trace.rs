//! The trace of `--verbose`, `--trace` and `--trace-ascii`
//! (`src/tool_cb_dbg.c`).

use std::fs::File;
use std::io::Write as _;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use curl_alloc::{OutOfMemory, TryArc, TryVec};
use curl_core::handler::{DebugHandler, DebugKind, Handler};
use curl_core::multi::TransferCx;
use curl_os::fs::{self, Keep};
use curl_os::time::local_time_of_day;

use crate::options::{Global, Trace};
use crate::stdout::Stdout;

/// What `fopen` creates a file with, before the umask.
const NEW_FILE_MODE: u32 = 0o666;

/// Stands for a byte that is not printable.
const UNPRINTABLE: u8 = b'.';

/// Where the trace goes, shared by every transfer's handler: the file is
/// opened at the first entry and stays open.
#[derive(Clone)]
pub(crate) struct Tracer(TryArc<Mutex<State>>);

struct State {
    kind: Trace,
    time: bool,
    /// `--trace-ids`.
    ids: bool,
    sink: Sink,
    /// `--verbose`'s last line is not ended yet.
    mid_line: bool,
    /// `--verbose` said data was not shown since the last other entry.
    noted_data: bool,
    /// Where an entry is put together, kept to be reused: tracing makes
    /// no allocation per entry once it has room for the largest.
    scratch: Vec<u8>,
}

enum Sink {
    Stdout(Stdout),
    Stderr,
    /// A file, by name with a zero byte after it, open once opened.
    File {
        name: Vec<u8>,
        file: Option<File>,
    },
}

impl Tracer {
    /// The tracer `global` asks for, if any.
    pub(crate) fn new(global: &Global<'_>, stdout: &Stdout) -> Result<Option<Tracer>, OutOfMemory> {
        if global.trace == Trace::None {
            return Ok(None);
        }
        let dump = global.trace_dump.expect("set with the trace");
        let sink = match dump {
            b"-" => Sink::Stdout(stdout.clone()),
            b"%" => Sink::Stderr,
            name => {
                let mut owned = Vec::new();
                owned.try_extend_from_slice(name)?;
                owned.try_push(0)?;
                Sink::File {
                    name: owned,
                    file: None,
                }
            }
        };
        let state = State {
            kind: global.trace,
            time: global.trace_time,
            ids: global.trace_ids,
            sink,
            mid_line: false,
            noted_data: false,
            scratch: Vec::new(),
        };
        Ok(Some(Tracer(TryArc::try_new(Mutex::new(state))?)))
    }

    /// The debug handler of one transfer; `terminal` says its output goes
    /// to a terminal.
    pub(crate) fn handler(&self, terminal: bool) -> Result<Handler<dyn DebugHandler>, OutOfMemory> {
        Handler::debug(Entry {
            tracer: self.clone(),
            terminal,
        })
    }
}

struct Entry {
    tracer: Tracer,
    terminal: bool,
}

impl Tracer {
    /// Trace an entry of the transfer `ids` names, if `--trace-ids` asks.
    fn entry(&self, kind: DebugKind, data: &[u8], terminal: bool, ids: TransferIds) {
        let mut state = self.0.lock().expect("no panic holds it");
        // Opened first: where the entry goes decides what `--verbose` says.
        state.sink.open();
        let mut out = std::mem::take(&mut state.scratch);
        out.clear();
        let stamp = state.time.then(timestamp);
        let stamp = stamp.as_ref().map_or(&b""[..], Stamp::bytes);
        let ids = state.ids.then(|| ids.text()).flatten();
        let ids = ids.as_ref().map_or(&b""[..], Stamp::bytes);
        let mut start = Stamp::empty();
        start.push(stamp);
        start.push(ids);
        let stamp = start.bytes();
        let written = match state.kind {
            Trace::Plain => plain(&mut state, &mut out, stamp, kind, data, terminal),
            Trace::Ascii | Trace::Binary => dump(&mut out, stamp, kind, data, state.kind),
            Trace::None => unreachable!("no handler without a trace"),
        };
        if written.is_ok() {
            state.sink.write(&out);
        }
        state.scratch = out;
    }
}

impl DebugHandler for Entry {
    fn debug(&self, cx: &mut TransferCx<'_>, kind: DebugKind, data: &[u8]) {
        let report = cx.info(cx.me());
        let ids = TransferIds {
            transfer: report.and_then(|r| r.transfer_number()),
            conn: report.and_then(|r| r.conn_number()),
        };
        self.tracer.entry(kind, data, self.terminal, ids);
    }
}

/// The numbers of the transfer an entry is of, and of its connection.
#[derive(Clone, Copy, Default)]
struct TransferIds {
    transfer: Option<u64>,
    conn: Option<u64>,
}

impl TransferIds {
    /// `[T-C] `, or `[T-x] ` without a connection; nothing without a
    /// transfer (`TRC_IDS_FORMAT_IDS_*`).
    fn text(self) -> Option<Stamp> {
        let transfer = self.transfer?;
        let mut text = Stamp::empty();
        // Two numbers of at most 20 digits fit.
        let _ = match self.conn {
            Some(conn) => write!(text, "[{transfer}-{conn}] "),
            None => write!(text, "[{transfer}-x] "),
        };
        Some(text)
    }
}

impl Sink {
    /// Create the trace file if it is not open yet. One that cannot be
    /// created leaves the entry to standard error, and is tried again for
    /// the next, as in C.
    fn open(&mut self) {
        if let Sink::File {
            name,
            file: file @ None,
        } = self
        {
            let c = core::ffi::CStr::from_bytes_with_nul(name)
                .expect("a file name, ended by a zero byte");
            *file = fs::open_write(c, Keep::Nothing, NEW_FILE_MODE).ok();
        }
    }

    /// Write an entry. A failed write has nowhere to be reported.
    fn write(&mut self, bytes: &[u8]) {
        let _ = match self {
            Sink::Stdout(out) => out.write_all(bytes),
            Sink::Stderr | Sink::File { file: None, .. } => std::io::stderr().write_all(bytes),
            Sink::File { file: Some(f), .. } => f.write_all(bytes),
        };
    }

    /// Whether entries go to standard output or error.
    fn is_standard(&self) -> bool {
        match self {
            Sink::Stdout(_) | Sink::Stderr => true,
            Sink::File { file, .. } => file.is_none(),
        }
    }
}

/// `HH:MM:SS.uuuuuu `, the local time of day: midnight where it cannot be
/// told, as C zeroes its `struct tm`.
fn timestamp() -> Stamp {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    let secs = i64::try_from(now.as_secs()).unwrap_or(i64::MAX);
    let day = local_time_of_day(secs).unwrap_or(curl_os::time::TimeOfDay {
        hour: 0,
        minute: 0,
        second: 0,
    });
    let mut stamp = Stamp::empty();
    // Every field is in range, so the stamp fits.
    let _ = write!(
        stamp,
        "{:02}:{:02}:{:02}.{:06} ",
        day.hour,
        day.minute,
        day.second,
        now.subsec_micros()
    );
    stamp
}

/// A timestamp or the ids, or both, on the stack.
struct Stamp {
    bytes: [u8; Stamp::LEN],
    len: usize,
}

impl Stamp {
    /// A timestamp, then two numbers of up to 20 digits in brackets.
    const LEN: usize = b"HH:MM:SS.uuuuuu ".len() + 2 * 20 + b"[-] ".len();

    fn empty() -> Stamp {
        Stamp {
            bytes: [0; Stamp::LEN],
            len: 0,
        }
    }

    fn push(&mut self, bytes: &[u8]) {
        let _ = std::io::Write::write_all(self, bytes);
    }

    fn bytes(&self) -> &[u8] {
        &self.bytes[..self.len]
    }
}

impl std::io::Write for Stamp {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let room = &mut self.bytes[self.len..];
        let n = buf.len().min(room.len());
        room[..n].copy_from_slice(&buf[..n]);
        self.len += n;
        Ok(n)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Formatted writes into a vector, failing when it cannot grow.
struct Bytes<'a>(&'a mut Vec<u8>);

impl std::io::Write for Bytes<'_> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0
            .try_extend_from_slice(buf)
            .map_err(|_| std::io::ErrorKind::OutOfMemory)?;
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn push(out: &mut Vec<u8>, bytes: &[u8]) -> Result<(), OutOfMemory> {
    out.try_extend_from_slice(bytes)
}

/// What starts a `--verbose` line of each kind.
fn marker(kind: DebugKind) -> &'static [u8] {
    match kind {
        DebugKind::Text => b"* ",
        DebugKind::HeaderIn => b"< ",
        DebugKind::HeaderOut => b"> ",
        DebugKind::DataIn | DebugKind::SslDataIn => b"{ ",
        DebugKind::DataOut | DebugKind::SslDataOut => b"} ",
    }
}

/// A `--verbose` entry: text and headers as lines, each started by its
/// marker; data only said to be there, once until something else comes.
fn plain(
    state: &mut State,
    out: &mut Vec<u8>,
    stamp: &[u8],
    kind: DebugKind,
    data: &[u8],
    terminal: bool,
) -> Result<(), OutOfMemory> {
    let start = |out: &mut Vec<u8>| -> Result<(), OutOfMemory> {
        push(out, stamp)?;
        push(out, marker(kind))
    };
    match kind {
        DebugKind::HeaderOut => {
            if let Some((&last, lines)) = data.split_last() {
                // Every line but a last one without its end gets the
                // marker, unless it continues the line before.
                let mut from = 0;
                for (i, &b) in lines.iter().enumerate() {
                    if b == b'\n' {
                        if !state.mid_line {
                            start(out)?;
                        }
                        push(out, &data[from..=i])?;
                        from = i + 1;
                        state.mid_line = false;
                    }
                }
                if !state.mid_line {
                    start(out)?;
                }
                push(out, &data[from..])?;
                state.mid_line = last != b'\n';
            } else {
                state.mid_line = false;
            }
            state.noted_data = false;
        }
        DebugKind::Text | DebugKind::HeaderIn => {
            if !state.mid_line {
                start(out)?;
            }
            push(out, data)?;
            state.mid_line = data.last().is_some_and(|&b| b != b'\n');
            state.noted_data = false;
        }
        DebugKind::DataIn | DebugKind::DataOut | DebugKind::SslDataIn | DebugKind::SslDataOut => {
            // Data shown on the terminal the trace goes to is not noted.
            if !state.noted_data && (!terminal || !state.sink.is_standard()) {
                if !state.mid_line {
                    start(out)?;
                }
                writeln!(Bytes(out), "[{} bytes data]", data.len()).map_err(|_| OutOfMemory)?;
                state.mid_line = false;
                state.noted_data = true;
            }
        }
    }
    Ok(())
}

/// A `--trace` or `--trace-ascii` entry: text as it is, anything else as
/// a dump.
fn dump(
    out: &mut Vec<u8>,
    stamp: &[u8],
    kind: DebugKind,
    data: &[u8],
    trace: Trace,
) -> Result<(), OutOfMemory> {
    let title: &[u8] = match kind {
        DebugKind::Text => {
            push(out, stamp)?;
            push(out, b"* ")?;
            return push(out, data);
        }
        DebugKind::HeaderOut => b"=> Send header",
        DebugKind::DataOut => b"=> Send data",
        DebugKind::HeaderIn => b"<= Recv header",
        DebugKind::DataIn => b"<= Recv data",
        DebugKind::SslDataIn => b"<= Recv SSL data",
        DebugKind::SslDataOut => b"=> Send SSL data",
    };
    let ascii = trace == Trace::Ascii;
    let mut w = Bytes(out);
    let oom = |_| OutOfMemory;
    w.0.try_extend_from_slice(stamp)?;
    w.0.try_extend_from_slice(title)?;
    writeln!(w, ", {} bytes (0x{:x})", data.len(), data.len()).map_err(oom)?;
    // Without the hexadecimal, more fits a line.
    let width = if ascii { 0x40 } else { 0x10 };
    let crlf_at = |i: usize| data.get(i) == Some(&b'\r') && data.get(i + 1) == Some(&b'\n');
    let mut i = 0;
    while i < data.len() {
        write!(w, "{i:04x}: ").map_err(oom)?;
        if !ascii {
            for c in 0..width {
                match data.get(i + c) {
                    Some(b) => write!(w, "{b:02x} ").map_err(oom)?,
                    None => w.0.try_extend_from_slice(b"   ")?,
                }
            }
        }
        // C's index arithmetic, unsigned: a CR LF ends the line, and the
        // next starts after it.
        let mut next = i + width;
        let mut c = 0;
        while c < width && i + c < data.len() {
            if ascii && crlf_at(i + c) {
                // Only ever at the line's start: anywhere else the check of
                // the byte after found it first.
                next = i + 2;
                break;
            }
            let b = data[i + c];
            w.0.try_push(if (0x20..0x7f).contains(&b) {
                b
            } else {
                UNPRINTABLE
            })?;
            if ascii && crlf_at(i + c + 1) {
                next = i + c + 3;
                break;
            }
            c += 1;
        }
        w.0.try_push(b'\n')?;
        i = next;
    }
    Ok(())
}

#[cfg(test)]
mod tests;
