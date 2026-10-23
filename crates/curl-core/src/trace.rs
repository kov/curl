//! What a transfer says about itself (`lib/curl_trc.c`): why it failed
//! (`failf`), kept in its report and traced, and the lines of text a
//! verbose transfer traces (`infof`). Both are formatted on the stack;
//! only the detail a report keeps is allocated.

use std::fmt;

use crate::components::Component;
use crate::conn::RecvFailed;
use crate::conn::io::{Recv, Sent};
use crate::error::{AGAIN_NUMBER, ErrorKind};
use crate::handler::DebugKind;
use crate::multi::state::StepCx;
use crate::multi::{Host, TransferCx};
use crate::progress;
use crate::text::Text;

/// C's longest trace line, its end included (`TRC_LINE_MAX`).
const LINE_MAX: usize = 2048;

/// C's longest failure detail, without its zero byte (`CURL_ERROR_SIZE`,
/// 256, less one).
pub(crate) const DETAIL_MAX: usize = 255;

/// A line for a verbose transfer's trace (`infof`): one cut short ends in
/// `...`, as C ends it.
pub(crate) fn info<H: Host>(cx: &mut StepCx<'_, H>, args: fmt::Arguments<'_>) {
    if !cx.easy().options().output.verbose {
        return;
    }
    let mut line = start_line(cx);
    line.push_fmt(args);
    end_line(&mut line);
    text(cx, line.bytes());
}

/// `info` with a line made of `parts`, which need not be text.
pub(crate) fn info_with<H: Host>(cx: &mut StepCx<'_, H>, parts: &[&[u8]]) {
    if !cx.easy().options().output.verbose {
        return;
    }
    let mut line = start_line(cx);
    for part in parts {
        line.push_clipped(part);
    }
    end_line(&mut line);
    text(cx, line.bytes());
}

/// Whether a verbose transfer traces `component`'s lines
/// (`Curl_trc_ft_is_verbose`, `Curl_trc_cf_is_verbose`): a caller with
/// work to do for a line asks first.
pub(crate) fn traces<H: Host>(cx: &StepCx<'_, H>, component: Component) -> bool {
    let easy = cx.easy();
    easy.options().output.verbose && easy.components().is_some_and(|c| c.traces(component))
}

/// A line of `component`'s (`CURL_TRC_WRITE`, `CURL_TRC_CF` and their
/// kind), after its name: traced when the transfer is verbose and the
/// component is on.
pub(crate) fn of<H: Host>(cx: &mut StepCx<'_, H>, component: Component, args: fmt::Arguments<'_>) {
    if !traces(cx, component) {
        return;
    }
    let mut line = start_line(cx);
    line.push_fmt(format_args!("[{}] ", component.name()));
    line.push_fmt(args);
    end_line(&mut line);
    text(cx, line.bytes());
}

/// What a send of `len` bytes on the connection came to (`cf_socket_send`).
pub(crate) fn sent<H: Host>(cx: &mut StepCx<'_, H>, len: usize, sent: &std::io::Result<Sent>) {
    let (code, n) = match sent {
        Ok(Sent::Bytes(n)) => (0, n.get()),
        Ok(Sent::WouldBlock) => (AGAIN_NUMBER, 0),
        Err(_) => (ErrorKind::SendError.number(), 0),
    };
    of(
        cx,
        Component::Tcp,
        format_args!("send(len={len}) -> {code}, {n}"),
    );
}

/// What a receive of up to `len` bytes on the connection came to
/// (`cf_socket_recv`).
pub(crate) fn received<H: Host>(
    cx: &mut StepCx<'_, H>,
    len: usize,
    got: &Result<Recv, RecvFailed>,
) {
    let (code, n) = match got {
        Ok(Recv::Data(n)) => (0, n.get()),
        Ok(Recv::Eof) => (0, 0),
        Ok(Recv::WouldBlock) => (AGAIN_NUMBER, 0),
        Err(RecvFailed::OutOfMemory) => (ErrorKind::OutOfMemory.number(), 0),
        Err(RecvFailed::Os(_)) => (ErrorKind::RecvError.number(), 0),
    };
    of(
        cx,
        Component::Tcp,
        format_args!("recv(len={len}) -> {code}, {n}"),
    );
}

/// `of` with a line made of `parts`, which need not be text.
pub(crate) fn of_with<H: Host>(cx: &mut StepCx<'_, H>, component: Component, parts: &[&[u8]]) {
    if !traces(cx, component) {
        return;
    }
    let mut line = start_line(cx);
    line.push_fmt(format_args!("[{}] ", component.name()));
    for part in parts {
        line.push_clipped(part);
    }
    end_line(&mut line);
    text(cx, line.bytes());
}

/// A result as C's trace lines print a `CURLcode` (`-> %d`).
pub(crate) struct Code(pub(crate) Result<(), ErrorKind>);

impl fmt::Display for Code {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.0 {
            Ok(()) => f.write_str("0"),
            Err(kind) => kind.number().fmt(f),
        }
    }
}

/// What every line starts with: the transfer's and its connection's
/// numbers, when the ids are on (`trc_print_ids`).
fn start_line<H: Host>(cx: &StepCx<'_, H>) -> Text<LINE_MAX> {
    let mut line = Text::<LINE_MAX>::new();
    push_ids(cx, &mut line);
    line
}

fn push_ids<H: Host, const N: usize>(cx: &StepCx<'_, H>, line: &mut Text<N>) {
    let easy = cx.easy();
    if !easy.components().is_some_and(|c| c.traces(Component::Ids)) {
        return;
    }
    let report = easy.report();
    line.push_fmt(format_args!(
        "[{}-{}] ",
        Ids(report.transfer_number()),
        Ids(report.conn_number())
    ));
}

/// A number in the ids, or `x` without one.
struct Ids(Option<u64>);

impl fmt::Display for Ids {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.0 {
            Some(n) => write!(f, "{n}"),
            None => f.write_str("x"),
        }
    }
}

/// A line for `info`, formatted while what it names is borrowed from the
/// transfer, to be traced with `info_line` once nothing is: the debug
/// handler may change the options it came from. It is ended as it is
/// traced, after what starts every line.
pub(crate) struct Line(Text<LINE_MAX>);

impl Line {
    /// The line as traced without ids, its end included.
    pub(crate) fn ended(&self) -> Text<LINE_MAX> {
        let mut line = self.0.clone();
        end_line(&mut line);
        line
    }
}

pub(crate) fn line(args: fmt::Arguments<'_>) -> Line {
    Line(Text::<LINE_MAX>::clipped(args).0)
}

/// `line` made of `parts`, which need not be text.
pub(crate) fn line_with(parts: &[&[u8]]) -> Line {
    let mut line = Text::<LINE_MAX>::new();
    for part in parts {
        line.push_clipped(part);
    }
    Line(line)
}

/// Trace a line `line` formatted, as `info` would have.
pub(crate) fn info_line<H: Host>(cx: &mut StepCx<'_, H>, line: &Line) {
    info_with(cx, &[line.0.bytes()]);
}

/// End a trace line (`trc_end_buf`): with a newline where it leaves room
/// for C's zero byte, else cut and marked `...`.
fn end_line(line: &mut Text<LINE_MAX>) {
    if line.bytes().len() >= LINE_MAX - 2 {
        line.truncate(LINE_MAX - 5);
        line.push_clipped(b"...\n");
    } else {
        line.push_clipped(b"\n");
    }
}

/// Why the transfer fails (`failf`): the first reason given is the one its
/// report keeps; every reason is traced.
pub(crate) fn fail<H: Host>(
    cx: &mut StepCx<'_, H>,
    kind: ErrorKind,
    args: fmt::Arguments<'_>,
) -> ErrorKind {
    failed(cx, kind, reason(args).0)
}

/// `fail` with a reason made of `parts`, which need not be text.
pub(crate) fn fail_with<H: Host>(
    cx: &mut StepCx<'_, H>,
    kind: ErrorKind,
    parts: &[&[u8]],
) -> ErrorKind {
    let mut detail = Text::<DETAIL_MAX>::new();
    for part in parts {
        detail.push_clipped(part);
    }
    failed(cx, kind, detail)
}

/// Why the transfer fails, formatted while what it names is borrowed
/// from the transfer, to be given with `fail_for` once nothing is.
pub(crate) struct Reason(Text<DETAIL_MAX>);

pub(crate) fn reason(args: fmt::Arguments<'_>) -> Reason {
    Reason(Text::<DETAIL_MAX>::clipped(args).0)
}

/// `fail` with a reason `reason` formatted.
pub(crate) fn fail_for<H: Host>(
    cx: &mut StepCx<'_, H>,
    kind: ErrorKind,
    reason: Reason,
) -> ErrorKind {
    failed(cx, kind, reason.0)
}

fn failed<H: Host>(cx: &mut StepCx<'_, H>, kind: ErrorKind, detail: Text<DETAIL_MAX>) -> ErrorKind {
    let first = cx.easy().report().reasons() == 0;
    cx.report_mut().record_failure(detail.bytes());
    if first && let Some(sink) = cx.easy().options().callbacks.failure.clone() {
        sink.write(detail.bytes());
    }
    if cx.easy().options().output.verbose {
        let mut line = Text::<{ DETAIL_MAX + 1 }>::new();
        line.push_clipped(detail.bytes());
        line.push_clipped(b"\n");
        text(cx, line.bytes());
    }
    kind
}

/// Bytes a verbose transfer traces (`Curl_debug`), after the ids when
/// they are on: to the debug handler with them, when what it is given
/// fits a trace line, or before the mark on standard error.
pub(crate) fn bytes<H: Host>(cx: &mut StepCx<'_, H>, kind: DebugKind, bytes: &[u8]) {
    let easy = cx.easy();
    if !easy.options().output.verbose {
        return;
    }
    let ids = easy.components().is_some_and(|c| c.traces(Component::Ids));
    if !ids {
        out(cx, kind, bytes, &[]);
        return;
    }
    let mut prefixed = Text::<LINE_MAX>::new();
    push_ids(cx, &mut prefixed);
    if easy.options().callbacks.debug.is_none() {
        out(cx, kind, bytes, prefixed.bytes());
    } else if bytes.len() < LINE_MAX {
        // As C ends a buffer it does not add a newline to: cut, and
        // marked `...`, where it leaves no room for a zero byte.
        prefixed.push_clipped(bytes);
        if prefixed.bytes().len() >= LINE_MAX - 1 {
            prefixed.truncate(LINE_MAX - 5);
            prefixed.push_clipped(b"...\n");
        }
        out(cx, kind, prefixed.bytes(), &[]);
    } else {
        out(cx, kind, bytes, &[]);
    }
}

/// Text to the debug handler, or without one to standard error after
/// `* `: a line, already started with the ids (`trc_write`).
fn text<H: Host>(cx: &mut StepCx<'_, H>, line: &[u8]) {
    out(cx, DebugKind::Text, line, &[]);
}

/// To the debug handler, or without one, text and headers to standard
/// error after `ids` and their mark.
fn out<H: Host>(cx: &mut StepCx<'_, H>, kind: DebugKind, bytes: &[u8], ids: &[u8]) {
    let options = cx.easy().options();
    match options.callbacks.debug.clone() {
        Some(handler) => handler.debug(&mut TransferCx::new(cx), kind, bytes),
        None => {
            let mark: &[u8] = match kind {
                DebugKind::Text => b"* ",
                DebugKind::HeaderIn => b"< ",
                DebugKind::HeaderOut => b"> ",
                DebugKind::DataIn
                | DebugKind::DataOut
                | DebugKind::SslDataIn
                | DebugKind::SslDataOut => return,
            };
            let sink = options.callbacks.stderr.as_ref();
            progress::to_stderr(sink, ids);
            progress::to_stderr(sink, mark);
            progress::to_stderr(sink, bytes);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A line that leaves room for C's newline and zero byte keeps all of
    /// itself; a longer one keeps 2043 bytes and `...`.
    #[test]
    fn ends_lines_as_c() {
        let ended = |len: usize| {
            let long = "x".repeat(len);
            let (mut line, _) = Text::<LINE_MAX>::clipped(format_args!("{long}"));
            end_line(&mut line);
            line.bytes().to_vec()
        };
        assert_eq!(ended(3), b"xxx\n");
        let fits = ended(LINE_MAX - 3);
        assert_eq!(fits.len(), LINE_MAX - 2);
        assert!(fits.ends_with(b"xx\n"));
        for len in [LINE_MAX - 2, LINE_MAX + 10] {
            let cut = ended(len);
            assert_eq!(cut.len(), LINE_MAX - 1, "{len}");
            assert!(cut.ends_with(b"x...\n"), "{len}");
        }
    }
}
