//! Delivering a transfer's output to the application's handlers: C's
//! client writer chain (`lib/sendf.c`, `lib/cw-out.c`) as one struct, in
//! the order of its fields.

mod decode;
mod held;
mod pause;
mod ws;

pub use pause::PauseRequest;
pub(crate) use pause::{Directions, Lifts, Pause, RecvPause};

use curl_alloc::TryVec;

use crate::coding::{Decoder, Sink};
use crate::components::Component;
use crate::error::ErrorKind;
use crate::handler::{DebugKind, HeaderOrigin, Write};
use crate::multi::state::StepCx;
use crate::multi::{Host, TransferCx};
use crate::progress::rate::Way;
use crate::proto::ftp::Matching;
use crate::report::Timer;
use crate::trace::{self, Code};
use decode::{Gate, Onward};
use held::{HeldOutput, OutKind};

/// The most body a write handler is given at once (`CURL_MAX_WRITE_SIZE`).
pub(crate) const MAX_WRITE: usize = 16384;

/// Where a protocol's output comes from (C's `PROTOPT_NONETWORK`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Reach {
    /// A connection: its input can stop while output is held, so a write
    /// may pause, and its header lines are kept for the headers API.
    Network,
    /// The local machine: a pausing write fails, and header lines are not
    /// kept.
    Local,
}

/// One request's output, from the protocol to the handlers.
#[derive(Debug)]
pub(crate) struct Pipeline {
    /// The codings to undo, and the gate in front of the content ones.
    /// Boxed: few responses have any, and every protocol's state carries
    /// a pipeline.
    codings: Option<Box<Codings>>,
    accountant: BodyAccountant,
    out: ClientOut,
    reach: Reach,
    /// C's chain of writers is made (`req.writer.stack`): by the first
    /// output, or at once for HTTP. The request's end is said of it only.
    made: bool,
    /// Header lines go to the write handler too, whatever the
    /// application set: while FTP writes one of its own
    /// (`client_write_header`).
    include_all: bool,
}

/// The most content codings a response may stack (`MAX_ENCODE_STACK`).
pub(crate) const MAX_CONTENT_CODINGS: usize = 5;

/// The content codings stacked, never more than [`MAX_CONTENT_CODINGS`]:
/// added only through a [`ContentRoom`], which a full stack gives none
/// of.
#[derive(Debug, Default)]
struct ContentStack(Vec<Box<dyn Decoder>>);

impl std::ops::Deref for ContentStack {
    type Target = [Box<dyn Decoder>];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl std::ops::DerefMut for ContentStack {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

/// Room for one more content coding in a request's output.
pub(crate) struct ContentRoom<'p> {
    pipeline: &'p mut Pipeline,
}

impl ContentRoom<'_> {
    /// Undo a content coding, after those added before it.
    pub(crate) fn add(self, decoder: Box<dyn Decoder>) -> Result<(), ErrorKind> {
        let stack = &mut self.pipeline.codings_for(&*decoder)?.content.0;
        assert!(
            stack.len() < MAX_CONTENT_CODINGS,
            "a room is given while there is room"
        );
        stack.try_push(decoder).map_err(|_| ErrorKind::OutOfMemory)
    }
}

/// A response's codings to undo, in the order of the chain.
#[derive(Debug, Default)]
struct Codings {
    /// The transfer codings to undo after chunked, before the body is
    /// counted (`CURL_CW_TRANSFER_DECODE`).
    transfer: Vec<Box<dyn Decoder>>,
    /// What holds output in front of the content decoders while a
    /// handler pauses, once a decoder that blows up is added
    /// (`cw-pause`, `cwriter_ensure_pause_writer`).
    gate: Option<Gate>,
    /// The content codings to undo, in the order the response gives them
    /// (`CURL_CW_CONTENT_DECODE`).
    content: ContentStack,
    /// A WebSocket's frames to decode, before the content codings
    /// (`ws_cw_decode`).
    ws: Option<ws::WsStage>,
}

impl Pipeline {
    pub(crate) fn new(reach: Reach) -> Pipeline {
        Pipeline {
            codings: None,
            accountant: BodyAccountant::default(),
            out: ClientOut::default(),
            reach,
            made: false,
            include_all: false,
        }
    }

    /// One whose chain is made at once, as HTTP's is: C installs its
    /// header collector as the connection is set up and as the request
    /// is made (`Curl_headers_init`).
    pub(crate) fn collecting() -> Pipeline {
        Pipeline {
            made: true,
            ..Pipeline::new(Reach::Network)
        }
    }

    /// The codings, made the first time a decoder is added; the gate
    /// made if `decoder` blows up.
    fn codings_for(&mut self, decoder: &dyn Decoder) -> Result<&mut Codings, ErrorKind> {
        self.made = true;
        let oom = |_| ErrorKind::OutOfMemory;
        if self.codings.is_none() {
            self.codings = Some(curl_alloc::try_box(Codings::default()).map_err(oom)?);
        }
        let codings = self.codings.as_mut().expect("made above");
        if decoder.blows_up() && codings.gate.is_none() {
            codings.gate = Some(Gate::default());
        }
        Ok(codings)
    }

    /// Undo a transfer coding, after those added before it.
    pub(crate) fn add_transfer_decoder(
        &mut self,
        decoder: Box<dyn Decoder>,
    ) -> Result<(), ErrorKind> {
        self.codings_for(&*decoder)?
            .transfer
            .try_push(decoder)
            .map_err(|_| ErrorKind::OutOfMemory)
    }

    /// The body is a WebSocket's frames, from here on: decoded unless
    /// `raw`, with the WebSocket's connection lent to the step whenever
    /// output is delivered (`Curl_ws_accept`).
    pub(crate) fn decode_websocket(&mut self, raw: bool) -> Result<(), ErrorKind> {
        self.made = true;
        if self.codings.is_none() {
            let codings = curl_alloc::try_box(Codings::default());
            self.codings = Some(codings.map_err(|_| ErrorKind::OutOfMemory)?);
        }
        self.codings.as_mut().expect("made above").ws = Some(ws::WsStage::new(raw));
        Ok(())
    }

    /// Whether the body is a WebSocket's frames, which its output is
    /// delivered with the connection lent for.
    pub(crate) fn decodes_websocket(&self) -> bool {
        self.codings.as_ref().is_some_and(|c| c.ws.is_some())
    }

    /// Room for one more content coding, if the stack is not full
    /// (`MAX_ENCODE_STACK`): the only way to add one.
    pub(crate) fn content_room(&mut self) -> Option<ContentRoom<'_>> {
        let stacked = self.codings.as_ref().map_or(0, |c| c.content.0.len());
        (stacked < MAX_CONTENT_CODINGS).then_some(ContentRoom { pipeline: self })
    }

    /// Whether the protocol can pause, its input and its output.
    pub(crate) fn pausable(&self) -> bool {
        self.reach == Reach::Network
    }

    /// Replay held output, unless a handler holds it still: the gate's,
    /// then the handlers', as C flushes its writers in the chain's order.
    pub(crate) fn flush<H: Host>(&mut self, cx: &mut StepCx<'_, H>) -> Result<(), ErrorKind> {
        let pausable = self.pausable();
        if let Some(Codings {
            gate: Some(gate),
            content,
            ws,
            ..
        }) = self.codings.as_deref_mut()
        {
            gate.flush(&mut Past {
                cx,
                decoders: content,
                ws: ws.as_mut(),
                out: &mut self.out,
                pausable,
                include_all: false,
            })?;
        }
        if let Some(Codings {
            content,
            ws: Some(ws),
            ..
        }) = self.codings.as_deref_mut()
        {
            return ws.flush(cx, &mut ws::After::new(content, &mut self.out, pausable));
        }
        self.out.flush(cx, pausable)
    }

    /// The body goes to `listing`, a wildcard download's, in place of
    /// the write handler, until it is given back.
    pub(crate) fn list_into(&mut self, listing: Box<Matching>) {
        self.out.listing = Some(listing);
    }

    /// The listing the body went to, if it did.
    pub(crate) fn listed(&mut self) -> Option<Box<Matching>> {
        self.out.listing.take()
    }

    /// Whether C's chain of writers is made, which the request's end is
    /// said of.
    pub(crate) fn made(&self) -> bool {
        self.made
    }

    /// The request's output is over (`Curl_cw_out_done`), its chain made:
    /// what is held goes with the request.
    pub(crate) fn done<H: Host>(cx: &mut StepCx<'_, H>) {
        write_trace(cx, format_args!("[OUT] done"));
        write_trace(cx, format_args!("client_flush() -> 0"));
    }

    /// Whether output is held: the request cannot be over until it is
    /// delivered.
    pub(crate) fn holds_output(&self) -> bool {
        self.out.holds_output()
            || self
                .codings
                .as_ref()
                .and_then(|c| c.gate.as_ref())
                .is_some_and(Gate::holds_output)
    }

    /// Give `bytes` to what comes after the accountant: the gate if there
    /// is one, then the decoders, then the handlers.
    fn onward<H: Host>(
        &mut self,
        cx: &mut StepCx<'_, H>,
        kind: OutKind,
        bytes: &[u8],
    ) -> Result<(), ErrorKind> {
        let pausable = self.pausable();
        let (gate, decoders, ws) = match self.codings.as_deref_mut() {
            Some(c) => (c.gate.as_mut(), &mut c.content.0[..], c.ws.as_mut()),
            None => (None, &mut [][..], None),
        };
        let mut past = Past {
            cx,
            decoders,
            ws,
            out: &mut self.out,
            pausable,
            include_all: self.include_all,
        };
        match gate {
            Some(gate) => gate.write(kind, bytes, &mut past),
            None => past.take(kind, bytes),
        }
    }

    /// The body's size, as the response announces it, or not
    /// (`Curl_pgrsSetDownloadSize`).
    pub(crate) fn announce_size<H: Host>(&mut self, cx: &mut StepCx<'_, H>, size: Option<u64>) {
        cx.report_mut().sizes_mut().download_expected = size;
    }

    /// What the response's head says the body comes to.
    pub(crate) fn expect(&mut self, expect: Expect) {
        self.accountant.expect = expect;
    }

    /// The body is complete: what more comes is no part of it (C's
    /// `download_done`).
    pub(crate) fn body_done(&self) -> bool {
        self.accountant.done
    }

    /// The body showed the connection cannot be reused: more came than was
    /// expected, or any where none was.
    pub(crate) fn body_closes(&self) -> bool {
        self.accountant.close
    }

    /// Body bytes delivered (C's `req.bytecount`).
    pub(crate) fn bytecount(&self) -> u64 {
        self.accountant.bytecount
    }

    /// Deliver body bytes as they came, traced first (`cw_raw_write`,
    /// then `decoded`). A body passes here once a packet, so this is
    /// inlined where the protocol delivers it: each trace is a check of
    /// verbose, made where it is said, with its line made out of line.
    #[inline]
    pub(crate) fn body<H: Host>(
        &mut self,
        cx: &mut StepCx<'_, H>,
        bytes: &[u8],
    ) -> Result<(), ErrorKind> {
        self.made = true;
        if cx.verbose() {
            self.raw_traced(cx, bytes);
        }
        let result = self.decoded(cx, bytes);
        if cx.verbose() {
            body_written(cx, bytes.len(), result);
        }
        result
    }

    /// `trace_raw`, out of the line `body` inlines.
    #[inline(never)]
    fn raw_traced<H: Host>(&self, cx: &mut StepCx<'_, H>, bytes: &[u8]) {
        self.trace_raw(cx, bytes);
    }

    /// Trace body bytes as they came, before a decoder takes them
    /// (`cw_raw_write`); an ignored body is not traced.
    pub(crate) fn trace_raw<H: Host>(&self, cx: &mut StepCx<'_, H>, bytes: &[u8]) {
        if !self.accountant.expect.ignore {
            raw_trace(cx, bytes);
        }
    }

    /// Deliver body bytes, already traced, of their transfer codings,
    /// through those to undo. Inlined, as `body` is, for a body with none.
    #[inline]
    pub(crate) fn decoded<H: Host>(
        &mut self,
        cx: &mut StepCx<'_, H>,
        bytes: &[u8],
    ) -> Result<(), ErrorKind> {
        if self.codings.as_ref().is_none_or(|c| c.transfer.is_empty()) {
            return self.counted(cx, bytes);
        }
        self.transfer_decoded(cx, bytes)
    }

    /// `decoded` through the transfer codings there are.
    #[inline(never)]
    fn transfer_decoded<H: Host>(
        &mut self,
        cx: &mut StepCx<'_, H>,
        bytes: &[u8],
    ) -> Result<(), ErrorKind> {
        let codings = self.codings.as_mut().expect("transfer codings to undo");
        // Out for the run, so that what they make reaches the rest.
        let mut transfer = std::mem::take(&mut codings.transfer);
        let result = decode::run(&mut transfer, bytes, &mut Counted { cx, pipeline: self });
        self.codings.as_mut().expect("taken from it").transfer = transfer;
        result
    }

    /// Deliver body bytes as the transfer decoders made them
    /// (`cw_download`): none when none was wanted, and no more than the
    /// expected size, what is past it noted and the connection given up.
    fn counted<H: Host>(&mut self, cx: &mut StepCx<'_, H>, bytes: &[u8]) -> Result<(), ErrorKind> {
        let expect = self.accountant.expect;
        self.accountant.response_started(cx);
        self.accountant.body_started(cx);
        if expect.no_body && !bytes.is_empty() {
            // The body goes; the response is fine if a head came.
            write_trace(
                cx,
                format_args!(
                    "download_write body(type={}, blen={}), did not want a BODY",
                    WriteType::BODY,
                    bytes.len()
                ),
            );
            self.accountant.close = true;
            self.accountant.done = true;
            return if expect.no_head {
                Err(ErrorKind::WeirdServerReply)
            } else {
                Ok(())
            };
        }
        let (wanted, excess) = self.accountant.cut(bytes.len());
        if expect.ignore {
            self.accountant.counted(cx, wanted);
            return Ok(());
        }
        let max_filesize = cx.easy().options().flow.max_filesize;
        let allowed = self.accountant.allowed(wanted, max_filesize);
        if allowed > 0 {
            let result = self.onward(cx, OutKind::Body, &bytes[..allowed]);
            if trace::traces(cx, Component::Write) {
                body_downloaded(cx, bytes.len(), result);
            }
            result?;
        }
        // Counted once the handlers are done with it: inside them, the
        // download size leaves out the write in progress.
        self.accountant.counted(cx, allowed);
        if excess > 0 {
            let bytecount = self.accountant.bytecount;
            trace::info(
                cx,
                format_args!(
                    "Excess found writing body: excess = {excess}, size = {}, maxdownload = {}, bytecount = {bytecount}",
                    CSize(expect.size),
                    CSize(expect.max)
                ),
            );
            self.accountant.close = true;
        } else if allowed < wanted {
            let max = max_filesize.expect("only a limit cuts the body short");
            let bytecount = self.accountant.bytecount;
            return Err(trace::fail(
                cx,
                ErrorKind::FilesizeExceeded,
                format_args!(
                    "Exceeded the maximum allowed file size ({max}) with {bytecount} bytes"
                ),
            ));
        }
        Ok(())
    }

    /// The response ended (`CLIENTWRITE_EOS`): a body of a known size must
    /// be whole. The end is traced as body of no bytes (`cw_raw_write`).
    pub(crate) fn end<H: Host>(&mut self, cx: &mut StepCx<'_, H>) -> Result<(), ErrorKind> {
        self.made = true;
        self.trace_raw(cx, &[]);
        let result = self.ended(cx);
        client_write(cx, WriteType::BODY.eos(), 0, result);
        result
    }

    fn ended<H: Host>(&mut self, cx: &mut StepCx<'_, H>) -> Result<(), ErrorKind> {
        self.accountant.body_started(cx);
        let expect = self.accountant.expect;
        let bytecount = self.accountant.bytecount;
        match expect.size {
            Some(size) if expect.max.is_some() && !expect.no_body && size > bytecount => {
                Err(trace::fail(
                    cx,
                    ErrorKind::PartialFile,
                    format_args!("end of response with {} bytes missing", size - bytecount),
                ))
            }
            _ => {
                // What ends the body goes through to the handlers, with
                // nothing to write; a WebSocket's frames must be whole.
                if !expect.ignore {
                    let pausable = self.pausable();
                    let ended = match self.codings.as_deref_mut() {
                        Some(Codings {
                            content,
                            ws: Some(ws),
                            ..
                        }) => {
                            let mut after = ws::After::new(content, &mut self.out, pausable);
                            ws.write(cx, &mut after, &[], true)
                        }
                        _ => Ok(()),
                    };
                    let eos = WriteType::BODY.eos();
                    write_trace(
                        cx,
                        format_args!("download_write body(type={eos}, blen=0) -> {}", Code(ended)),
                    );
                    return ended;
                }
                Ok(())
            }
        }
    }

    /// Deliver one header line, whole: into the report's header store
    /// from a network, then to the write handler if the headers are
    /// included in the output, then to the header handler.
    pub(crate) fn header<H: Host>(
        &mut self,
        cx: &mut StepCx<'_, H>,
        line: &[u8],
        origin: HeaderOrigin,
    ) -> Result<(), ErrorKind> {
        self.made = true;
        if self.reach == Reach::Network {
            let pushed = cx.report_mut().headers_mut().push(line, origin);
            let stored = match origin {
                HeaderOrigin::Header => 1,
                HeaderOrigin::Trailer => 2,
                HeaderOrigin::Connect => 4,
                HeaderOrigin::Interim => 8,
            };
            write_trace(
                cx,
                format_args!(
                    "header_collect pushed(type={stored:x}, len={}) -> {}",
                    line.len(),
                    Code(pushed)
                ),
            );
            pushed?;
        }
        let kind = OutKind::Header(origin);
        let result = self.head_line(cx, line, kind);
        // A trailer comes from the chunked decoder, past the chain's
        // start.
        if origin != HeaderOrigin::Trailer {
            client_write(cx, WriteType::of(kind), line.len(), result);
        }
        result
    }

    /// Deliver header bytes of a protocol outside HTTP's family, to the
    /// write handler if headers are included and to the header handler,
    /// and not kept for the headers API: C collects headers for HTTP
    /// only (`Curl_headers_init`). Gopher's selector is one.
    pub(crate) fn protocol_header<H: Host>(
        &mut self,
        cx: &mut StepCx<'_, H>,
        bytes: &[u8],
    ) -> Result<(), ErrorKind> {
        self.made = true;
        let kind = OutKind::Header(HeaderOrigin::Header);
        let result = self.head_line(cx, bytes, kind);
        client_write(cx, WriteType::of(kind), bytes.len(), result);
        result
    }

    /// Deliver a line of a line protocol's answer, which is no header:
    /// to the header handler alone, whether or not headers are included
    /// in the output, and not kept for the headers API
    /// (`CLIENTWRITE_INFO`). It starts the response's time only once the
    /// request's body is sent, as C counts it (`cw_download_write`).
    pub(crate) fn info<H: Host>(
        &mut self,
        cx: &mut StepCx<'_, H>,
        line: &[u8],
        upload_done: bool,
    ) -> Result<(), ErrorKind> {
        self.made = true;
        if upload_done {
            self.accountant.response_started(cx);
        }
        let result = self.onward(cx, OutKind::Info, line);
        write_trace(
            cx,
            format_args!(
                "download_write header(type={}, blen={}) -> {}",
                WriteType::of(OutKind::Info),
                line.len(),
                Code(result)
            ),
        );
        client_write(cx, WriteType::of(OutKind::Info), line.len(), result);
        result
    }

    /// Deliver a header line FTP makes up for what it found out
    /// (`Content-Length:`, `Last-Modified:`, `Accept-ranges:`), to the
    /// write handler as well as the header handler whatever the
    /// application set, as FTP always did, and not kept for the headers
    /// API (ftp.c's `client_write_header`).
    pub(crate) fn included_header<H: Host>(
        &mut self,
        cx: &mut StepCx<'_, H>,
        line: &[u8],
    ) -> Result<(), ErrorKind> {
        self.made = true;
        let kind = OutKind::Header(HeaderOrigin::Header);
        self.include_all = true;
        let result = self.head_line(cx, line, kind);
        self.include_all = false;
        client_write(cx, WriteType::of(kind), line.len(), result);
        result
    }

    /// Deliver a response's status line, of an informational response
    /// (1xx) or not, as a header line the store does not keep
    /// (`CLIENTWRITE_STATUS`).
    pub(crate) fn status<H: Host>(
        &mut self,
        cx: &mut StepCx<'_, H>,
        line: &[u8],
        interim: bool,
    ) -> Result<(), ErrorKind> {
        self.made = true;
        let origin = match interim {
            true => HeaderOrigin::Interim,
            false => HeaderOrigin::Header,
        };
        let kind = OutKind::Status(origin);
        let result = self.head_line(cx, line, kind);
        client_write(cx, WriteType::of(kind), line.len(), result);
        result
    }

    /// Deliver a proxy's answer to `CONNECT`'s status line, which the
    /// store does not keep either.
    pub(crate) fn connect_status<H: Host>(
        &mut self,
        cx: &mut StepCx<'_, H>,
        line: &[u8],
    ) -> Result<(), ErrorKind> {
        self.made = true;
        let kind = OutKind::Status(HeaderOrigin::Connect);
        let result = self.head_line(cx, line, kind);
        client_write(cx, WriteType::of(kind), line.len(), result);
        result
    }

    fn head_line<H: Host>(
        &mut self,
        cx: &mut StepCx<'_, H>,
        line: &[u8],
        kind: OutKind,
    ) -> Result<(), ErrorKind> {
        if kind.origin() != Some(HeaderOrigin::Connect) {
            self.accountant.response_started(cx);
        } else if cx.easy().options().proxy.suppress_connect_headers
            || (cfg!(feature = "debug-hooks")
                && curl_os::env::is_set(b"CURL_DBG_SUPPRESS_CONNECT_HDS"))
        {
            // The debug test build suppresses them on request as well, as
            // C's `cw_download_write` does, whatever the application set.
            return Ok(());
        }
        let result = self.onward(cx, kind, line);
        write_trace(
            cx,
            format_args!(
                "download_write header(type={}, blen={}) -> {}",
                WriteType::of(kind),
                line.len(),
                Code(result)
            ),
        );
        result
    }
}

/// A line of the write trace (`CURL_TRC_WRITE`): its check inlined where
/// it is said, as `trace::of`'s is, so that a line not traced costs no
/// call.
#[inline]
fn write_trace<H: Host>(cx: &mut StepCx<'_, H>, args: std::fmt::Arguments<'_>) {
    trace::of(cx, Component::Write, args);
}

/// What a write at the chain's start came to (`Curl_client_write`).
#[inline]
pub(crate) fn client_write<H: Host>(
    cx: &mut StepCx<'_, H>,
    kind: WriteType,
    len: usize,
    result: Result<(), ErrorKind>,
) {
    write_trace(
        cx,
        format_args!("client_write(type={kind}, len={len}) -> {}", Code(result)),
    );
}

/// What the body's bytes past the accountant came to (`cw_download_write`),
/// out of the line `Pipeline::counted` makes.
#[inline(never)]
fn body_downloaded<H: Host>(cx: &mut StepCx<'_, H>, blen: usize, result: Result<(), ErrorKind>) {
    write_trace(
        cx,
        format_args!(
            "download_write body(type={}, blen={blen}) -> {}",
            WriteType::BODY,
            Code(result)
        ),
    );
}

/// `client_write` of body bytes, out of the line `Pipeline::body` inlines.
#[inline(never)]
fn body_written<H: Host>(cx: &mut StepCx<'_, H>, len: usize, result: Result<(), ErrorKind>) {
    client_write(cx, WriteType::BODY, len, result);
}

/// What a protocol's read of the response came to (`Curl_xfer_write_resp`):
/// the check inlined where it is said, the line made out of line, as a
/// read hands on a body once a packet.
#[inline]
pub(crate) fn write_resp<H: Host>(
    cx: &mut StepCx<'_, H>,
    len: usize,
    eos: bool,
    result: Result<(), ErrorKind>,
) {
    if trace::traces(cx, Component::Write) {
        write_resp_traced(cx, len, eos, result);
    }
}

#[inline(never)]
fn write_resp_traced<H: Host>(
    cx: &mut StepCx<'_, H>,
    len: usize,
    eos: bool,
    result: Result<(), ErrorKind>,
) {
    write_trace(
        cx,
        format_args!(
            "xfer_write_resp(len={len}, eos={}) -> {}",
            u8::from(eos),
            Code(result)
        ),
    );
}

/// What kind of output a write is, as C's client writers mark it
/// (`CLIENTWRITE_*`): only printed, by the write trace.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct WriteType(u16);

impl WriteType {
    pub(crate) const BODY: WriteType = WriteType(1);
    const INFO: u16 = 1 << 1;
    const HEADER: u16 = 1 << 2;
    const STATUS: u16 = 1 << 3;
    const CONNECT: u16 = 1 << 4;
    const INTERIM: u16 = 1 << 5;
    const TRAILER: u16 = 1 << 6;
    const EOS: u16 = 1 << 7;

    pub(crate) fn of(kind: OutKind) -> WriteType {
        let origin = |origin| match origin {
            HeaderOrigin::Header => 0,
            HeaderOrigin::Connect => Self::CONNECT,
            HeaderOrigin::Interim => Self::INTERIM,
            HeaderOrigin::Trailer => Self::TRAILER,
        };
        match kind {
            OutKind::Body | OutKind::EmptyBody => Self::BODY,
            OutKind::Info => WriteType(Self::INFO),
            OutKind::Header(o) => WriteType(Self::HEADER | origin(o)),
            OutKind::Status(o) => WriteType(Self::HEADER | Self::STATUS | origin(o)),
        }
    }

    /// The same, the last of the response (`CLIENTWRITE_EOS`).
    pub(crate) fn eos(self) -> WriteType {
        WriteType(self.0 | Self::EOS)
    }
}

impl std::fmt::Display for WriteType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:x}", self.0)
    }
}

/// What the transfer decoders write to: the accountant, and the rest.
struct Counted<'p, 'c, H: Host> {
    cx: &'p mut StepCx<'c, H>,
    pipeline: &'p mut Pipeline,
}

impl<H: Host> Sink for Counted<'_, '_, H> {
    fn write(&mut self, bytes: &[u8]) -> Result<(), ErrorKind> {
        self.pipeline.counted(self.cx, bytes)
    }

    fn timed_out(&self) -> bool {
        self.cx.time_up()
    }

    fn fail(&mut self, kind: ErrorKind, said: std::fmt::Arguments<'_>) -> ErrorKind {
        trace::fail(self.cx, kind, said)
    }
}

/// What is past the gate: the decoders, which pass header lines by, then
/// the handlers.
struct Past<'p, 'c, H: Host> {
    cx: &'p mut StepCx<'c, H>,
    decoders: &'p mut [Box<dyn Decoder>],
    ws: Option<&'p mut ws::WsStage>,
    out: &'p mut ClientOut,
    pausable: bool,
    include_all: bool,
}

impl<H: Host> Onward for Past<'_, '_, H> {
    fn paused(&self) -> bool {
        handler_paused(self.cx)
    }

    fn trace(&mut self, args: std::fmt::Arguments<'_>) {
        write_trace(self.cx, args);
    }

    fn take(&mut self, kind: OutKind, bytes: &[u8]) -> Result<(), ErrorKind> {
        let (cx, out, pausable) = (&mut *self.cx, &mut *self.out, self.pausable);
        match kind {
            OutKind::Body => match self.ws.as_deref_mut() {
                Some(ws) => {
                    let mut after = ws::After::new(&mut *self.decoders, out, pausable);
                    ws.write(cx, &mut after, bytes, false)
                }
                None => decode::run(self.decoders, bytes, &mut Client { cx, out, pausable }),
            },
            OutKind::EmptyBody => unreachable!("only a WebSocket's frames are empty body"),
            // Never body, whatever is included (`cw_out_write`).
            OutKind::Info => out.header(cx, bytes, kind, pausable),
            OutKind::Header(_) | OutKind::Status(_) => {
                // An included line is body, to be held and replayed with it.
                if self.include_all || cx.easy().options().output.include_header {
                    out.body(cx, bytes, pausable)?;
                }
                out.header(cx, bytes, kind, pausable)
            }
        }
    }
}

/// The handlers, as the last decoder's sink.
struct Client<'p, 'c, H: Host> {
    cx: &'p mut StepCx<'c, H>,
    out: &'p mut ClientOut,
    pausable: bool,
}

impl<H: Host> Sink for Client<'_, '_, H> {
    fn write(&mut self, bytes: &[u8]) -> Result<(), ErrorKind> {
        self.out.body(self.cx, bytes, self.pausable)
    }

    fn timed_out(&self) -> bool {
        self.cx.time_up()
    }

    fn fail(&mut self, kind: ErrorKind, said: std::fmt::Arguments<'_>) -> ErrorKind {
        trace::fail(self.cx, kind, said)
    }
}

/// A handler asked for a pause: output stops at once and is held. One the
/// application asked for from inside a handler does not stop it.
fn handler_paused<H: Host>(cx: &StepCx<'_, H>) -> bool {
    cx.pause().recv == RecvPause::Held
}

/// The body as received, before any decoding, to the debug handler of a
/// verbose transfer (`cw_raw_write`).
fn raw_trace<H: Host>(cx: &mut StepCx<'_, H>, bytes: &[u8]) {
    trace::bytes(cx, DebugKind::DataIn, bytes);
}

/// What a response's head says its body comes to (C's `req.size`,
/// `req.maxdownload` and `req.no_body`); nothing, before a head or
/// without one.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct Expect {
    /// The size the head gives.
    pub(crate) size: Option<u64>,
    /// The most body to deliver, past which the rest is excess.
    pub(crate) max: Option<u64>,
    /// No body is wanted.
    pub(crate) no_body: bool,
    /// No head came before the body (HTTP/0.9).
    pub(crate) no_head: bool,
    /// The body is read, counted and dropped: neither written nor traced
    /// nor held to a limit (`ignorebody`).
    pub(crate) ignore: bool,
}

/// A size as C prints one: -1 for none.
struct CSize(Option<u64>);

impl std::fmt::Display for CSize {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.0 {
            Some(n) => n.fmt(f),
            None => f.write_str("-1"),
        }
    }
}

/// What a request's body came to, and the limits on it (`cw_download`).
#[derive(Debug, Default)]
struct BodyAccountant {
    /// Body bytes past the accountant (C's `req.bytecount`).
    bytecount: u64,
    /// Something of the response, not of a proxy's CONNECT, has come.
    started: bool,
    /// The body has: the receive limit started over with it
    /// (`started_body`).
    body_started: bool,
    expect: Expect,
    /// The body is complete.
    done: bool,
    /// The connection is not to be reused.
    close: bool,
}

impl BodyAccountant {
    /// The response's first output: STARTTRANSFER.
    fn response_started<H: Host>(&mut self, cx: &mut StepCx<'_, H>) {
        if !self.started {
            self.started = true;
            cx.mark(Timer::StartTransfer);
        }
    }

    /// The body's first write, of bytes or of its end: the receive limit
    /// starts over, tuned for the size expected (`cw_download_write`).
    fn body_started<H: Host>(&mut self, cx: &mut StepCx<'_, H>) {
        if !self.body_started {
            self.body_started = true;
            cx.rate_start(Way::Recv, self.expect.size);
        }
    }

    /// `n` body bytes counted: the receive limit takes them
    /// (`Curl_pgrs_download_inc`).
    fn counted<H: Host>(&mut self, cx: &mut StepCx<'_, H>, n: usize) {
        if n > 0 {
            self.bytecount += n as u64;
            cx.downloaded(n);
        }
    }

    /// How much of `len` more bytes the expected size wants, and how many
    /// are past it; the body is complete once it has them all.
    fn cut(&mut self, len: usize) -> (usize, usize) {
        let Some(max) = self.expect.max else {
            return (len, 0);
        };
        let left = usize::try_from(max.saturating_sub(self.bytecount)).unwrap_or(usize::MAX);
        let wanted = len.min(left);
        if wanted == left {
            self.done = true;
        }
        (wanted, len - wanted)
    }

    /// How much of `len` more bytes the size limit lets through.
    fn allowed(&self, len: usize, max_filesize: Option<std::num::NonZeroU64>) -> usize {
        let Some(max) = max_filesize else {
            return len;
        };
        let left = max.get().saturating_sub(self.bytecount);
        usize::try_from(left).map_or(len, |left| len.min(left))
    }
}

/// The last stage: the handlers (`cw-out`).
#[derive(Debug, Default)]
struct ClientOut {
    state: OutState,
    /// While a wildcard download's listing is read, the body goes to its
    /// reader in place of the write handler (`Curl_ftp_listmode`).
    listing: Option<Box<Matching>>,
}

/// How output reaches the handlers.
#[derive(Debug, Default)]
enum OutState {
    /// Writing straight to the handlers.
    #[default]
    Direct,
    /// Output a write handler paused on, held until it is replayed, with
    /// what came after it.
    Held(HeldOutput),
    /// A write failed: no handler is called again (#13337).
    Failed,
}

impl ClientOut {
    /// Write `bytes` to the write handler in pieces of at most
    /// `MAX_WRITE`, reading the handler again before each; held, if output
    /// is held already.
    fn body<H: Host>(
        &mut self,
        cx: &mut StepCx<'_, H>,
        bytes: &[u8],
        pausable: bool,
    ) -> Result<(), ErrorKind> {
        let result = self.write(cx, OutKind::Body, bytes, pausable);
        self.fail_on(result)
    }

    /// Call the write handler with nothing, for a WebSocket frame of no
    /// payload; held after what is held.
    fn empty_body<H: Host>(
        &mut self,
        cx: &mut StepCx<'_, H>,
        pausable: bool,
    ) -> Result<(), ErrorKind> {
        let result = self.write(cx, OutKind::EmptyBody, &[], pausable);
        self.fail_on(result)
    }

    fn header<H: Host>(
        &mut self,
        cx: &mut StepCx<'_, H>,
        line: &[u8],
        kind: OutKind,
        pausable: bool,
    ) -> Result<(), ErrorKind> {
        let result = self.write(cx, kind, line, pausable);
        self.fail_on(result)
    }

    /// Replay held output until it is all delivered or a handler pauses
    /// again (`cw_out_flush_chain`).
    fn flush<H: Host>(&mut self, cx: &mut StepCx<'_, H>, pausable: bool) -> Result<(), ErrorKind> {
        if matches!(self.state, OutState::Held(_)) && !handler_paused(cx) {
            write_trace(cx, format_args!("[OUT] flush"));
        }
        let result = self.replay(cx, pausable);
        self.fail_on(result)
    }

    fn write<H: Host>(
        &mut self,
        cx: &mut StepCx<'_, H>,
        kind: OutKind,
        bytes: &[u8],
        pausable: bool,
    ) -> Result<(), ErrorKind> {
        // Output of another kind than the last held tries what is held
        // first (`cw_out_do_write`).
        if let OutState::Held(held) = &self.state
            && held.last_kind().map(out_type) != Some(out_type(kind))
        {
            self.replay(cx, pausable)?;
        }
        match &mut self.state {
            OutState::Failed => Err(ErrorKind::WriteError),
            OutState::Held(held) => {
                buffering(cx, bytes.len(), held.held());
                held.append(kind, bytes)?;
                self.replay(cx, pausable)
            }
            OutState::Direct => {
                let delivered = deliver(cx, kind, bytes, pausable, self.listing.as_deref_mut())?;
                if delivered < bytes.len() {
                    let mut held = HeldOutput::default();
                    buffering(cx, bytes.len() - delivered, 0);
                    held.append(kind, &bytes[delivered..])?;
                    self.state = OutState::Held(held);
                }
                Ok(())
            }
        }
    }

    fn replay<H: Host>(&mut self, cx: &mut StepCx<'_, H>, pausable: bool) -> Result<(), ErrorKind> {
        let held = match &mut self.state {
            OutState::Failed => return Err(ErrorKind::WriteError),
            OutState::Direct => return Ok(()),
            OutState::Held(held) => held,
        };
        // Only a handler's own pause stops the replay, and it is the only
        // thing that leaves an entry part delivered.
        while !handler_paused(cx) {
            let Some((kind, bytes)) = held.front() else {
                break;
            };
            let delivered = deliver(cx, kind, bytes, pausable, self.listing.as_deref_mut())?;
            held.consume(delivered);
        }
        if held.is_empty() {
            self.state = OutState::Direct;
        }
        Ok(())
    }

    /// Any error ends the output for good.
    fn fail_on(&mut self, result: Result<(), ErrorKind>) -> Result<(), ErrorKind> {
        if result.is_err() {
            self.state = OutState::Failed;
        }
        result
    }

    fn holds_output(&self) -> bool {
        matches!(self.state, OutState::Held(_))
    }
}

/// What C's output writer buffers `kind` as (`cw_out_type`).
fn out_type(kind: OutKind) -> u8 {
    match kind {
        OutKind::Body => 1,
        OutKind::EmptyBody => 2,
        OutKind::Header(_) | OutKind::Status(_) | OutKind::Info => 3,
    }
}

/// The handlers paused, so `len` more bytes are held after `held`.
fn buffering<H: Host>(cx: &mut StepCx<'_, H>, len: usize, held: usize) {
    write_trace(
        cx,
        format_args!(
            "[OUT] paused, buffering {len} more bytes ({held}/{})",
            held::MAX_HELD
        ),
    );
}

/// What a handler's answer comes to as C's callback returns it, traced
/// after each call (`cw_out_cb_write`): the bytes it took, or
/// `CURL_WRITEFUNC_PAUSE` or `CURL_WRITEFUNC_ERROR`. The check is
/// inlined where the handler is called, and only a line traced is made.
#[inline]
fn wrote<H: Host>(cx: &mut StepCx<'_, H>, kind: OutKind, len: usize, w: Write) {
    if trace::traces(cx, Component::Write) {
        wrote_traced(cx, kind, len, w);
    }
}

#[inline(never)]
fn wrote_traced<H: Host>(cx: &mut StepCx<'_, H>, kind: OutKind, len: usize, w: Write) {
    let what = match kind {
        OutKind::Body | OutKind::EmptyBody => "body",
        OutKind::Header(_) | OutKind::Status(_) | OutKind::Info => "header",
    };
    let otype = out_type(kind);
    let took: u64 = match w {
        Write::Accepted => len as u64,
        Write::Took(took) => took as u64,
        Write::Pause => 0x1000_0001,
        Write::Fail => 0xffff_ffff,
    };
    write_trace(
        cx,
        format_args!("[OUT] wrote {len} {what} bytes, type={otype:x} -> {took}"),
    );
}

/// Give `bytes` to the handler for `kind`, body in pieces, until a handler
/// pauses; how much it took. A paused piece is not taken: it is given
/// again, whole, when the transfer goes on (`cw_out_ptr_flush`).
fn deliver<H: Host>(
    cx: &mut StepCx<'_, H>,
    kind: OutKind,
    bytes: &[u8],
    pausable: bool,
    listing: Option<&mut Matching>,
) -> Result<usize, ErrorKind> {
    match kind {
        OutKind::Body => deliver_body(cx, bytes, pausable, listing),
        OutKind::EmptyBody => {
            let Some(handler) = cx.easy().options().callbacks.write.clone() else {
                return Ok(0);
            };
            let reasons = cx.easy().report().reasons();
            let w = handler.write(&mut TransferCx::new(cx), &[]);
            wrote(cx, kind, 0, w);
            verdict(cx, w, 0, reasons, pausable)?;
            Ok(0)
        }
        OutKind::Header(_) | OutKind::Status(_) | OutKind::Info => {
            // A line protocol's lines are told as a head's.
            let origin = kind.origin().unwrap_or(HeaderOrigin::Header);
            let Some(handler) = cx.easy().options().callbacks.header.clone() else {
                return Ok(bytes.len());
            };
            let reasons = cx.easy().report().reasons();
            let w = handler.header(&mut TransferCx::new(cx), bytes, origin);
            wrote(cx, kind, bytes.len(), w);
            Ok(if verdict(cx, w, bytes.len(), reasons, pausable)? {
                bytes.len()
            } else {
                0
            })
        }
    }
}

fn deliver_body<H: Host>(
    cx: &mut StepCx<'_, H>,
    bytes: &[u8],
    pausable: bool,
    mut listing: Option<&mut Matching>,
) -> Result<usize, ErrorKind> {
    let mut delivered = 0;
    for piece in bytes.chunks(MAX_WRITE) {
        let easy = cx.easy();
        let handler = easy.options().callbacks.write.clone();
        if handler.is_none() && listing.is_none() {
            return Ok(bytes.len());
        }
        // Body bytes delivered, included header lines among them (C's
        // `progress.deliver`).
        let so_far = easy.report().sizes().delivered();
        let reasons = easy.report().reasons();
        if let Some(max) = easy.options().flow.max_filesize
            && piece.len() as u64 > max.get().saturating_sub(so_far)
        {
            let kind = ErrorKind::FilesizeExceeded;
            return Err(trace::fail(
                cx,
                kind,
                format_args!("Would have exceeded max file size"),
            ));
        }
        let w = match (listing.as_deref_mut(), handler) {
            (Some(listing), _) => {
                listing.take(cx, piece);
                Write::Accepted
            }
            (None, Some(handler)) => handler.write(&mut TransferCx::new(cx), piece),
            (None, None) => unreachable!("one of them takes the body"),
        };
        wrote(cx, OutKind::Body, piece.len(), w);
        if !verdict(cx, w, piece.len(), reasons, pausable)? {
            break;
        }
        cx.report_mut().sizes_mut().delivered += piece.len() as u64;
        delivered += piece.len();
    }
    Ok(delivered)
}

/// Whether the handler took what it was given; a pause holds the output
/// from here on. A handler that failed with a reason of its own, given
/// since the transfer had `reasons`, is not given another.
fn verdict<H: Host>(
    cx: &mut StepCx<'_, H>,
    w: Write,
    len: usize,
    reasons: u32,
    pausable: bool,
) -> Result<bool, ErrorKind> {
    match w {
        Write::Accepted => Ok(true),
        Write::Took(took) if took == len => Ok(true),
        Write::Took(took) => Err(trace::fail(
            cx,
            ErrorKind::WriteError,
            format_args!("Failure writing output to destination, passed {len} returned {took}"),
        )),
        Write::Pause if !pausable => Err(trace::fail(
            cx,
            ErrorKind::WriteError,
            format_args!("Write callback asked for PAUSE when not supported"),
        )),
        Write::Pause => {
            cx.pause_mut().recv = RecvPause::Held;
            write_trace(cx, format_args!("[OUT] PAUSE requested by client"));
            Ok(false)
        }
        Write::Fail if cx.easy().report().reasons() != reasons => Err(ErrorKind::WriteError),
        Write::Fail => Err(trace::fail(
            cx,
            ErrorKind::WriteError,
            format_args!("client returned ERROR on write of {len} bytes"),
        )),
    }
}

#[cfg(test)]
mod tests;
