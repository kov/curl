//! What a transfer says about itself (`lib/curl_trc.c`): why it failed
//! (`failf`), kept in its report and traced, and the lines of text a
//! verbose transfer traces (`infof`). Both are formatted on the stack;
//! only the detail a report keeps is allocated.

use std::fmt;

use crate::components::{Component, Components};
use crate::conn::io::Sent;
use crate::conn::{ConnNumber, TransferNumber};
use crate::error::{AGAIN_NUMBER, ErrorKind};
use crate::handler::DebugKind;
use crate::multi::raw::Notes;
use crate::multi::state::{ConnRank, StepCx};
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
    push_doing(cx, &mut line);
    line.push_fmt(args);
    end_line(&mut line);
    text(cx, line.bytes());
}

/// The work of the multi's a transfer is doing before its lines, but for
/// those of other kinds that name their own (`trc_infof`'s
/// `data->state.feat`): `[DoH]`, for a probe.
fn push_doing<H: Host>(cx: &StepCx<'_, H>, line: &mut Text<LINE_MAX>) {
    if let Some(doing) = cx.easy().doing() {
        line.push_fmt(format_args!("[{}] ", doing.name()));
    }
}

/// A line only C's debug build traces (`DEBUGF(infof(...))`): `info`
/// in the debug-hooks build, nothing in any other.
pub(crate) fn debug_info<H: Host>(cx: &mut StepCx<'_, H>, args: fmt::Arguments<'_>) {
    if cfg!(feature = "debug-hooks") {
        info(cx, args);
    }
}

/// `debug_info` with a line made of `parts`, which need not be text.
pub(crate) fn debug_info_with<H: Host>(cx: &mut StepCx<'_, H>, parts: &[&[u8]]) {
    if cfg!(feature = "debug-hooks") {
        info_with(cx, parts);
    }
}

/// Whether `line` is one `debug_info` writes for C's debug build, for
/// the tests that read a trace whole, whichever build runs them.
#[cfg(test)]
pub(crate) fn debug_only(line: &[u8]) -> bool {
    [
        &b"sending last upload chunk of "[..],
        b"Curl_xfer_send(",
        b"Curl_req_flush(",
        b"cr_exp100_read, ",
        b"sendrecv_dl",
        b"Curl_sendrecv() -> ",
        b"Alt-svc check wanted=",
        b"check Alt-Svc for host ",
    ]
    .iter()
    .any(|p| line.starts_with(p))
}

/// `info` with a line made of `parts`, which need not be text.
pub(crate) fn info_with<H: Host>(cx: &mut StepCx<'_, H>, parts: &[&[u8]]) {
    if !cx.easy().options().output.verbose {
        return;
    }
    let mut line = start_line(cx);
    push_doing(cx, &mut line);
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
    handle_traces(cx.easy(), component)
}

/// `traces`, of a handle whatever it is doing.
pub(crate) fn handle_traces(easy: &crate::easy::Easy, component: Component) -> bool {
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
    if component.is_filter() {
        push_doing(cx, &mut line);
    }
    push_name(cx, &mut line, component);
    line.push_fmt(args);
    end_line(&mut line);
    text(cx, line.bytes());
}

/// `component`'s name before its line: a filter of the second chain's
/// with the socket's index (`trc_infof`'s `sockindex`).
fn push_name<H: Host>(cx: &StepCx<'_, H>, line: &mut Text<LINE_MAX>, component: Component) {
    let name = component.name();
    if cx.rank() == ConnRank::Second && component.is_filter() {
        line.push_fmt(format_args!("[{name}-1] "));
    } else {
        line.push_fmt(format_args!("[{name}] "));
    }
}

/// What a send of `len` bytes on the connection came to (`cf_socket_send`),
/// in the socket's filter's name, `component`.
pub(crate) fn sent<H: Host>(
    cx: &mut StepCx<'_, H>,
    component: Component,
    len: usize,
    sent: &std::io::Result<Sent>,
) {
    let (code, n) = match sent {
        Ok(Sent::Bytes(n)) => (0, n.get()),
        Ok(Sent::WouldBlock) => (AGAIN_NUMBER, 0),
        Err(_) => (ErrorKind::SendError.number(), 0),
    };
    of(
        cx,
        component,
        format_args!("send(len={len}) -> {code}, {n}"),
    );
}

/// `of` with a line made of `parts`, which need not be text.
pub(crate) fn of_with<H: Host>(cx: &mut StepCx<'_, H>, component: Component, parts: &[&[u8]]) {
    if !traces(cx, component) {
        return;
    }
    let mut line = start_line(cx);
    if component.is_filter() {
        push_doing(cx, &mut line);
    }
    push_name(cx, &mut line, component);
    for part in parts {
        line.push_clipped(part);
    }
    end_line(&mut line);
    text(cx, line.bytes());
}

/// A line of transfer `calls.me()`'s trace outside its step (`infof` on
/// a handle a callback of the multi was given): after its ids, through
/// its debug handler, or without one to its standard error.
pub(crate) fn info_outside(calls: &mut dyn crate::multi::TransferCalls, args: fmt::Arguments<'_>) {
    let Some(easy) = calls.own() else {
        return;
    };
    let options = easy.options();
    if !options.output.verbose {
        return;
    }
    let mut line = Text::<LINE_MAX>::new();
    push_ids_of(easy, &mut line);
    line.push_fmt(args);
    end_line(&mut line);
    let handler = options.callbacks.debug.clone();
    let sink = options.callbacks.stderr.clone();
    match handler {
        Some(handler) => handler.debug(&mut TransferCx::new(calls), DebugKind::Text, line.bytes()),
        None => {
            progress::to_stderr(sink.as_ref(), b"* ");
            progress::to_stderr(sink.as_ref(), line.bytes());
        }
    }
}

/// A line of `component`'s on `easy` outside any multi, as it is reset or
/// let go of (`Curl_close`): after its ids, through its debug handler, or
/// without one to its standard error.
pub(crate) fn of_lone(
    easy: &mut crate::easy::Easy,
    me: crate::multi::TransferId,
    component: Component,
    args: fmt::Arguments<'_>,
) {
    if !easy.options().output.verbose || !handle_traces(easy, component) {
        return;
    }
    let mut line = Text::<LINE_MAX>::new();
    push_ids_of(easy, &mut line);
    line.push_fmt(format_args!("[{}] ", component.name()));
    line.push_fmt(args);
    end_line(&mut line);
    let handler = easy.options().callbacks.debug.clone();
    let sink = easy.options().callbacks.stderr.clone();
    match handler {
        Some(handler) => {
            let mut calls = crate::multi::LoneCalls { easy, me };
            handler.debug(
                &mut TransferCx::new(&mut calls),
                DebugKind::Text,
                line.bytes(),
            );
        }
        None => {
            progress::to_stderr(sink.as_ref(), b"* ");
            progress::to_stderr(sink.as_ref(), line.bytes());
        }
    }
}

/// A line of `component`'s, or with none of the verbose output, of a
/// call on the connection `easy`'s transfer left: as a transfer's, after
/// its ids.
pub(crate) fn note_line(
    easy: &crate::easy::Easy,
    component: Option<Component>,
    notes: Notes<'_>,
    said: impl FnOnce(&mut Text<LINE_MAX>),
) {
    let on = component.is_none_or(|c| easy.components().is_some_and(|on| on.traces(c)));
    if !easy.options().output.verbose || !on {
        return;
    }
    let mut line = Text::<LINE_MAX>::new();
    push_ids_of(easy, &mut line);
    if let Some(component) = component {
        line.push_fmt(format_args!("[{}] ", component.name()));
    }
    said(&mut line);
    end_line(&mut line);
    notes(DebugKind::Text, line.bytes());
}

/// Bytes of a call on the connection `easy`'s transfer left, for its debug
/// handler (`Curl_debug`): none without one, as standard error shows no
/// such bytes.
pub(crate) fn note_bytes(
    easy: &crate::easy::Easy,
    kind: DebugKind,
    bytes: &[u8],
    notes: Notes<'_>,
) {
    if !easy.options().output.verbose || easy.options().callbacks.debug.is_none() {
        return;
    }
    let ids = easy.components().is_some_and(|c| c.traces(Component::Ids));
    if ids && bytes.len() < LINE_MAX {
        let mut prefixed = Text::<LINE_MAX>::new();
        push_ids_of(easy, &mut prefixed);
        after_ids(&mut prefixed, bytes);
        notes(kind, prefixed.bytes());
    } else {
        notes(kind, bytes);
    }
}

/// Why a call on the connection `easy`'s transfer left fails, as `failed`
/// traces it: its detail alone, with no ids.
pub(crate) fn note_failure(easy: &crate::easy::Easy, detail: &[u8], notes: Notes<'_>) {
    if easy.options().output.verbose {
        let mut line = Text::<{ DETAIL_MAX + 1 }>::new();
        line.push_clipped(detail);
        line.push_clipped(b"\n");
        notes(DebugKind::Text, line.bytes());
    }
}

/// The trace of work done for no transfer, C's internal handle's
/// (`multi->admin`): its lines, a component's when that is on, to standard
/// error after `* `, as a verbose handle with no debug function writes
/// them, and with no numbers when the ids are on. C's debug build makes
/// that handle verbose under `CURL_DEBUG`; the components are the
/// process's, every handle's.
#[derive(Clone)]
pub(crate) struct Internal {
    components: Components,
    /// Where its lines go instead of standard error, for the tests.
    sink: Option<crate::handler::Handler<dyn crate::handler::TextSink>>,
}

impl fmt::Debug for Internal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Internal").finish_non_exhaustive()
    }
}

impl Internal {
    pub(crate) fn new(components: Components) -> Internal {
        Internal {
            components,
            sink: None,
        }
    }

    /// One whose lines go to `sink`.
    #[cfg(test)]
    pub(crate) fn to(
        components: Components,
        sink: crate::handler::Handler<dyn crate::handler::TextSink>,
    ) -> Internal {
        Internal {
            components,
            sink: Some(sink),
        }
    }

    pub(crate) fn traces(&self, component: Component) -> bool {
        self.components.traces(component)
    }

    /// A line of no component's (`infof`).
    pub(crate) fn info(&self, args: fmt::Arguments<'_>) {
        self.write(None, |line| {
            line.push_fmt(args);
        });
    }

    /// `info` with a line made of `parts`, which need not be text.
    pub(crate) fn info_with(&self, parts: &[&[u8]]) {
        self.write(None, |line| {
            for part in parts {
                line.push_clipped(part);
            }
        });
    }

    /// A line of `component`'s, if it is on (`CURL_TRC_M`,
    /// `CURL_TRC_CF`).
    pub(crate) fn of(&self, component: Component, args: fmt::Arguments<'_>) {
        if self.traces(component) {
            self.write(Some(component), |line| {
                line.push_fmt(args);
            });
        }
    }

    /// `of` with a line made of `parts`, which need not be text.
    pub(crate) fn of_with(&self, component: Component, parts: &[&[u8]]) {
        if self.traces(component) {
            self.write(Some(component), |line| {
                for part in parts {
                    line.push_clipped(part);
                }
            });
        }
    }

    fn write(&self, component: Option<Component>, said: impl FnOnce(&mut Text<LINE_MAX>)) {
        let mut line = Text::<LINE_MAX>::new();
        if self.traces(Component::Ids) {
            line.push_fmt(format_args!("[{}-{}] ", Ids(None), Ids(None)));
        }
        if let Some(component) = component {
            line.push_fmt(format_args!("[{}] ", component.name()));
        }
        said(&mut line);
        end_line(&mut line);
        progress::to_stderr(self.sink.as_ref(), b"* ");
        progress::to_stderr(self.sink.as_ref(), line.bytes());
    }
}

/// The context of work done for no transfer: traced on the internal
/// handle's trace, if there is one, and kept nowhere; a multi's work
/// lends the multi's receive room, as C's admin handle borrows its
/// multi's (`Curl_multi_xfer_sockbuf_borrow`).
#[derive(Debug)]
pub(crate) struct InternalCx<'a> {
    pub(crate) now: crate::time::Instant,
    pub(crate) trace: Option<&'a Internal>,
    pub(crate) room: Option<&'a mut crate::conn::quic::RecvRoom>,
}

impl crate::conn::layer::LayerCx for InternalCx<'_> {
    fn now(&self) -> crate::time::Instant {
        self.now
    }

    fn trace(&mut self) -> Option<&mut dyn crate::conn::layer::Trace> {
        self.trace
            .as_mut()
            .map(|trace| trace as &mut dyn crate::conn::layer::Trace)
    }

    fn failures(&mut self) -> Option<&mut dyn crate::conn::layer::Failures> {
        None
    }

    fn transfer(&mut self) -> Option<&mut dyn crate::conn::layer::ForTransfer> {
        None
    }

    fn tls_sessions(&mut self) -> Option<&mut dyn crate::conn::layer::TlsSessions> {
        None
    }

    fn early_data(&mut self) -> Option<&mut dyn crate::conn::layer::EarlyData> {
        None
    }

    fn quic_timer(&mut self) -> Option<&mut dyn crate::conn::layer::QuicTimer> {
        None
    }

    fn h3_streams(&mut self) -> Option<&mut dyn crate::conn::layer::H3Streams> {
        None
    }

    fn recv_room(&mut self) -> Option<&mut crate::conn::quic::RecvRoom> {
        self.room.as_deref_mut()
    }
}

/// The internal handle's trace, whose lines are said whatever the
/// transfer's verbosity.
impl crate::conn::layer::Trace for &Internal {
    fn line(&mut self, component: Component, line: fmt::Arguments<'_>) {
        self.of(component, line);
    }

    fn line_with(&mut self, component: Component, parts: &[&[u8]]) {
        self.of_with(component, parts);
    }

    fn info_line(&mut self, line: fmt::Arguments<'_>) {
        self.info(line);
    }

    fn info_line_with(&mut self, parts: &[&[u8]]) {
        self.info_with(parts);
    }

    fn says_info(&self) -> bool {
        true
    }
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
    push_ids_of(cx.easy(), line);
}

fn push_ids_of<const N: usize>(easy: &crate::easy::Easy, line: &mut Text<N>) {
    if !easy.components().is_some_and(|c| c.traces(Component::Ids)) {
        return;
    }
    let report = easy.report();
    line.push_fmt(format_args!(
        "[{}-{}] ",
        Ids(report.transfer_number().map(TransferNumber::get)),
        Ids(report.conn_number().map(ConnNumber::get))
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
    /// An empty line, to be built of pieces: `text` formatted on the
    /// stack, and `raw` bytes of the peer's or the application's, as C's
    /// `%s` writes them.
    pub(crate) fn new() -> Line {
        Line(Text::new())
    }

    /// Add `args`, formatted: numbers, and text of our own.
    pub(crate) fn text(&mut self, args: fmt::Arguments<'_>) -> &mut Line {
        self.0.push_fmt(args);
        self
    }

    /// Add `bytes` as they are, which need not be text.
    pub(crate) fn raw(&mut self, bytes: &[u8]) -> &mut Line {
        self.0.push_clipped(bytes);
        self
    }

    /// What the line holds, not ended.
    pub(crate) fn bytes(&self) -> &[u8] {
        self.0.bytes()
    }

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

/// Let go of the reason kept for the transfer's failure, the next one
/// given kept in its place, and empty what the application was told
/// of it (`Curl_reset_fail`).
pub(crate) fn reset_fail<H: Host>(cx: &mut StepCx<'_, H>) {
    if cx.report_mut().reset_failure()
        && let Some(sink) = cx.easy().options().callbacks.failure.clone()
    {
        sink.write(b"");
    }
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

impl Reason {
    pub(crate) fn bytes(&self) -> &[u8] {
        self.0.bytes()
    }
}

pub(crate) fn reason(args: fmt::Arguments<'_>) -> Reason {
    Reason(Text::<DETAIL_MAX>::clipped(args).0)
}

/// `reason` made of `parts`, which need not be text.
pub(crate) fn reason_with(parts: &[&[u8]]) -> Reason {
    let mut detail = Text::<DETAIL_MAX>::new();
    for part in parts {
        detail.push_clipped(part);
    }
    Reason(detail)
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
    let first = cx.easy().report().unsaid();
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
        after_ids(&mut prefixed, bytes);
        out(cx, kind, prefixed.bytes(), &[]);
    } else {
        out(cx, kind, bytes, &[]);
    }
}

/// `bytes`, after the ids `prefixed` holds, as C ends a buffer it does not
/// add a newline to: cut, and marked `...`, where it leaves no room for a
/// zero byte.
fn after_ids(prefixed: &mut Text<LINE_MAX>, bytes: &[u8]) {
    prefixed.push_clipped(bytes);
    if prefixed.bytes().len() >= LINE_MAX - 1 {
        prefixed.truncate(LINE_MAX - 5);
        prefixed.push_clipped(b"...\n");
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

/// A local address, or C's empty one when none is known.
pub(crate) struct Ip(pub(crate) Option<std::net::IpAddr>);

impl fmt::Display for Ip {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.0 {
            Some(ip) => ip.fmt(f),
            None => Ok(()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// What a raw call's notes hear.
    fn heard(call: impl FnOnce(Notes<'_>)) -> Vec<Vec<u8>> {
        let mut heard = Vec::new();
        call(&mut |_, b: &[u8]| heard.push(b.to_vec()));
        heard
    }

    /// A handle with a debug handler, verbose or not, tracing ids or not.
    fn tracing(verbose: bool, handler: bool, ids: bool) -> crate::easy::Easy {
        struct Nothing;
        impl crate::handler::DebugHandler for Nothing {
            fn debug(&self, _: &mut crate::multi::TransferCx<'_>, _: DebugKind, _: &[u8]) {}
        }
        let mut e = crate::easy::Easy::new();
        e.options_mut().output.verbose = verbose;
        if handler {
            e.options_mut().callbacks.debug =
                Some(crate::handler::Handler::debug(Nothing).unwrap());
        }
        if ids {
            let components = crate::components::Components::new().unwrap();
            components.configure(b"lib-ids");
            e.set_components(Some(components));
        }
        e
    }

    /// A raw call's bytes reach a verbose handle's debug handler and only
    /// that; with ids on, those short of a line are prefixed with them.
    #[test]
    fn a_raw_call_s_bytes_go_to_a_verbose_debug_handler() {
        let note = |e: &crate::easy::Easy, bytes: &[u8]| {
            heard(|notes| note_bytes(e, DebugKind::Text, bytes, notes))
        };
        assert!(note(&tracing(false, true, false), b"x").is_empty());
        assert!(note(&tracing(true, false, false), b"x").is_empty());
        assert_eq!(note(&tracing(true, true, false), b"x"), [b"x".to_vec()]);
        let ids = tracing(true, true, true);
        assert_eq!(note(&ids, b"x"), [b"[x-x] x".to_vec()]);
        for len in [LINE_MAX, LINE_MAX + 1] {
            let long = vec![b'x'; len];
            assert_eq!(
                note(&ids, &long),
                std::slice::from_ref(&long),
                "as they are"
            );
        }
        let just_short = vec![b'x'; LINE_MAX - 1];
        assert!(note(&ids, &just_short)[0].starts_with(b"[x-x] "));
    }

    /// Why a raw call failed is traced to a verbose handle whole, with its
    /// newline, at the longest a reason can be.
    #[test]
    fn a_raw_call_s_failure_keeps_its_newline() {
        let e = tracing(true, false, false);
        let detail = vec![b'x'; DETAIL_MAX];
        let lines = heard(|notes| note_failure(&e, &detail, notes));
        assert_eq!(lines[0].len(), DETAIL_MAX + 1);
        assert!(lines[0].ends_with(b"x\n"));
    }

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
