//! What a transfer says about itself (`lib/curl_trc.c`): why it failed
//! (`failf`), kept in its report and traced, and the lines of text a
//! verbose transfer traces (`infof`). Both are formatted on the stack;
//! only the detail a report keeps is allocated.

use std::fmt;

use crate::error::ErrorKind;
use crate::handler::DebugKind;
use crate::multi::state::StepCx;
use crate::multi::{Host, TransferCx};
use crate::progress;
use crate::text::Text;

/// C's longest trace line, its end included (`TRC_LINE_MAX`).
#[cfg_attr(
    not(any(test, feature = "debug-hooks")),
    expect(dead_code, reason = "the debug build's warning is the only line yet")
)]
const LINE_MAX: usize = 2048;

/// C's longest failure detail, without its zero byte (`CURL_ERROR_SIZE`,
/// 256, less one).
pub(crate) const DETAIL_MAX: usize = 255;

/// A line for a verbose transfer's trace (`infof`): one cut short ends in
/// `...`, as C ends it.
#[cfg_attr(
    not(feature = "debug-hooks"),
    expect(dead_code, reason = "the debug build's warning is the only line yet")
)]
pub(crate) fn info<H: Host>(cx: &mut StepCx<'_, H>, args: fmt::Arguments<'_>) {
    if !cx.easy().options().output.verbose {
        return;
    }
    let (mut line, _) = Text::<LINE_MAX>::clipped(args);
    end_line(&mut line);
    text(cx, line.bytes());
}

/// End a trace line (`trc_end_buf`): with a newline where it leaves room
/// for C's zero byte, else cut and marked `...`.
#[cfg_attr(
    not(any(test, feature = "debug-hooks")),
    expect(dead_code, reason = "the debug build's warning is the only line yet")
)]
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
    let (detail, _) = Text::<DETAIL_MAX>::clipped(args);
    failed(cx, kind, detail)
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

/// Text to the debug handler, or without one to standard error after
/// `* ` (`Curl_debug`).
fn text<H: Host>(cx: &mut StepCx<'_, H>, line: &[u8]) {
    let options = cx.easy().options();
    match options.callbacks.debug.clone() {
        Some(handler) => handler.debug(&mut TransferCx::new(cx), DebugKind::Text, line),
        None => {
            let sink = options.callbacks.stderr.as_ref();
            progress::to_stderr(sink, b"* ");
            progress::to_stderr(sink, line);
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
