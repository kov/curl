//! What a request reads of its body: the source, then the stages C stacks
//! above its client reader (`Curl_creader_add`), each with its own buffer.

use curl_alloc::{OutOfMemory, TryVec as _, try_box};

use crate::components::Component;
use crate::error::ErrorKind;
use crate::multi::Host;
use crate::multi::state::StepCx;
use crate::proto::http1::chunked::ChunkEncoder;
use crate::trace;

use super::{Readout, Upload};

/// The trailers a chunked body ends with, each line with its CRLF.
pub(crate) type Trailers<H> = fn(&mut StepCx<'_, H>) -> Result<Vec<u8>, ErrorKind>;

/// A request's body: its source and the stages above it.
#[derive(Debug)]
pub(crate) struct Body {
    upload: Upload,
    chain: Chain,
}

/// The stages between the source and the request, one slot for each of
/// C's reader phases, read from the last: each frames what the one below
/// it gives into its own buffer.
#[derive(Debug, Default)]
struct Chain {
    /// `CURL_CR_TRANSFER_ENCODE`: HTTP/1's chunks (`cr_chunked`).
    chunks: Option<ChunkEncoder>,
    /// `CURL_CR_CONTENT_ENCODE`, first in its phase: a mail's dots
    /// escaped and its end marked (`cr-smtp-eob`), reading from the
    /// conversion below it; boxed, as the conversion is.
    mail: Option<Box<MailEnd>>,
    /// `CURL_CR_CONTENT_ENCODE`: each lone LF sent as CRLF
    /// (`cr-lineconv`); boxed, as few bodies are converted and every
    /// transfer's state holds its body inline.
    lines: Option<Box<LineConv>>,
}

/// A stage's read of the one below it.
type Stage<'s, H> = dyn FnMut(&mut StepCx<'_, H>, &mut [u8]) -> Result<Readout, ErrorKind> + 's;

/// What ends an SMTP mail body: CRLF, a dot, CRLF (`SMTP_EOB`).
const MAIL_END: &[u8; 5] = b"\r\n.\r\n";

/// How much of [`MAIL_END`] is matched before a dot is added: a line's
/// start and its dot (`SMTP_EOB_FIND_LEN`).
const DOT_AT_START: usize = 3;

/// A mail body as SMTP's `DATA` sends it (`cr_eob_read`): a dot that
/// starts a line doubled, and the body ended with a line of a single
/// dot, after a CRLF of its own unless the body ends with one. What it
/// gives that it changed waits in its buffer for the reads after; a read
/// with nothing to change goes on as it is.
#[derive(Debug)]
pub(crate) struct MailEnd {
    /// What was changed and not yet given, from `at` on.
    buf: Vec<u8>,
    at: usize,
    /// How much of [`MAIL_END`] the bytes so far end with (`n_eob`): the
    /// body's first byte starts a line, as if after a CRLF.
    matched: usize,
    /// The source ended (`read_eos`).
    read_eos: bool,
    /// The end's line was added (`processed_eos`).
    ended: bool,
    /// The end was given (`eos`).
    eos: bool,
}

impl Default for MailEnd {
    fn default() -> MailEnd {
        MailEnd {
            buf: Vec::new(),
            at: 0,
            matched: 2,
            read_eos: false,
            ended: false,
            eos: false,
        }
    }
}

impl MailEnd {
    /// Read into `dest`, which is not empty, from `below` changed.
    fn read<H: Host>(
        &mut self,
        cx: &mut StepCx<'_, H>,
        below: &mut Stage<'_, H>,
        dest: &mut [u8],
    ) -> Result<Readout, ErrorKind> {
        let len = dest.len();
        if !self.read_eos && self.held().is_empty() {
            let got = below(cx, dest);
            let (code, n, eos) = match &got {
                Ok(got) => (trace::Code(Ok(())), got.n, got.eos),
                Err(e) => (trace::Code(Err(*e)), 0, false),
            };
            let eos = u8::from(eos);
            trace::of(
                cx,
                Component::Smtp,
                format_args!("cr_eob_read, next_read(len={len}) -> {code}, {n} eos={eos}"),
            );
            let got = got?;
            self.read_eos = got.eos;
            let read = &dest[..got.n];
            if !read.is_empty() {
                if self.passes(read) {
                    // Nothing matched and no line's end to start a match:
                    // given as it came, its end said with the next read.
                    return Ok(Readout {
                        n: got.n,
                        eos: false,
                    });
                }
                self.stuff(read).map_err(|_| ErrorKind::OutOfMemory)?;
            }
        }
        if self.read_eos && !self.ended {
            trace::of(
                cx,
                Component::Smtp,
                format_args!("auto-ending mail body with '\\r\\n.\\r\\n'"),
            );
            self.end().map_err(|_| ErrorKind::OutOfMemory)?;
        }
        let n = self.give(dest);
        if self.read_eos && self.held().is_empty() {
            trace::of(
                cx,
                Component::Smtp,
                format_args!("mail body complete, returning EOS"),
            );
            self.eos = true;
        }
        let eos = u8::from(self.eos);
        trace::debug_info(cx, format_args!("cr_eob_read({len}) -> 0, {n}, {eos}"));
        Ok(Readout { n, eos: self.eos })
    }

    /// What it holds to give.
    fn held(&self) -> &[u8] {
        &self.buf[self.at..]
    }

    /// Whether `read` goes on unchanged: no part of the end is matched
    /// and nothing in it starts one.
    fn passes(&self, read: &[u8]) -> bool {
        self.matched == 0 && !read.contains(&MAIL_END[0])
    }

    /// Take `read` into the buffer, a dot added before what follows a
    /// line's starting dot.
    fn stuff(&mut self, read: &[u8]) -> Result<(), OutOfMemory> {
        self.compact();
        let dots = read.iter().filter(|&&b| b == b'.').count();
        self.buf
            .try_reserve(read.len() + dots)
            .map_err(|_| OutOfMemory)?;
        for &b in read {
            if self.matched >= DOT_AT_START {
                self.buf.try_push(b'.').expect("reserved");
                self.matched = 0;
            }
            if b != MAIL_END[self.matched] {
                self.matched = 0;
            }
            if b == MAIL_END[self.matched] {
                self.matched += 1;
            }
            self.buf.try_push(b).expect("reserved");
        }
        Ok(())
    }

    /// Add the line that ends the body: the rest of the end after a CRLF
    /// or an empty body, the line's dot doubled first after a line that
    /// starts with one, or the whole end.
    fn end(&mut self) -> Result<(), OutOfMemory> {
        self.compact();
        let end: &[u8] = match self.matched {
            2 => &MAIL_END[2..],
            DOT_AT_START => b".\r\n.\r\n",
            _ => MAIL_END,
        };
        self.buf.try_extend_from_slice(end)?;
        self.ended = true;
        Ok(())
    }

    /// Give what it holds into `dest`, as much as fits.
    fn give(&mut self, dest: &mut [u8]) -> usize {
        let held = self.held();
        let n = held.len().min(dest.len());
        dest[..n].copy_from_slice(&held[..n]);
        self.at += n;
        n
    }

    /// The buffer emptied of what was given.
    fn compact(&mut self) {
        if self.at == self.buf.len() {
            self.buf.clear();
            self.at = 0;
        }
    }
}

/// The line ends of a body converted, each LF not after a CR sent as CRLF
/// (`cr_lc_read`). Whatever it gives that holds a converted LF waits in
/// its buffer for the reads after; a read with no LF to convert goes on
/// as it is.
#[derive(Debug, Default)]
pub(crate) struct LineConv {
    /// What was converted and not yet given, from `at` on.
    buf: Vec<u8>,
    at: usize,
    /// The source ended.
    read_eos: bool,
    /// The end was given.
    eos: bool,
    /// The last byte read was a CR, which the next LF ends a line with.
    prev_cr: bool,
}

impl LineConv {
    /// Read into `dest`, which is not empty, from `upload` converted.
    fn read<H: Host>(
        &mut self,
        cx: &mut StepCx<'_, H>,
        upload: &mut Upload,
        dest: &mut [u8],
        pausable: bool,
    ) -> Result<Readout, ErrorKind> {
        if self.eos {
            return Ok(Readout { n: 0, eos: true });
        }
        let len = dest.len();
        if self.at == self.buf.len() {
            if self.read_eos {
                self.eos = true;
                return Ok(Readout { n: 0, eos: true });
            }
            let got = upload.read(cx, dest, pausable)?;
            self.read_eos = got.eos;
            let read = &dest[..got.n];
            if !read.contains(&b'\n') {
                // Nothing to convert: given as it came.
                if let Some(&last) = read.last() {
                    self.prev_cr = last == b'\r';
                }
                self.eos = self.read_eos;
                return Ok(self.traced(cx, len, got.n));
            }
            self.convert(read).map_err(|_| ErrorKind::OutOfMemory)?;
        }
        let n = (self.buf.len() - self.at).min(len);
        dest[..n].copy_from_slice(&self.buf[self.at..self.at + n]);
        self.at += n;
        self.eos = self.read_eos && self.at == self.buf.len();
        Ok(self.traced(cx, len, n))
    }

    /// `read`, converted into the buffer, which is empty.
    fn convert(&mut self, read: &[u8]) -> Result<(), OutOfMemory> {
        self.buf.clear();
        self.at = 0;
        let lfs = read.iter().filter(|&&b| b == b'\n').count();
        self.buf
            .try_reserve(read.len() + lfs)
            .map_err(|_| OutOfMemory)?;
        for &b in read {
            if b == b'\n' && !self.prev_cr {
                self.buf.try_push(b'\r').expect("reserved");
            }
            self.prev_cr = b == b'\r';
            self.buf.try_push(b).expect("reserved");
        }
        Ok(())
    }

    /// A read that gave `n` into room for `len`, traced.
    fn traced<H: Host>(&self, cx: &mut StepCx<'_, H>, len: usize, n: usize) -> Readout {
        let eos = u8::from(self.eos);
        trace::of(
            cx,
            Component::Read,
            format_args!("cr_lc_read(len={len}) -> 0, nread={n}, eos={eos}"),
        );
        Readout { n, eos: self.eos }
    }
}

impl Body {
    /// `upload` read as it is.
    pub(crate) fn new(upload: Upload) -> Body {
        Body {
            upload,
            chain: Chain::default(),
        }
    }

    /// Sent chunked: the chunk stage added (`Curl_httpchunk_add_reader`).
    pub(crate) fn chunked(&mut self) -> Result<(), OutOfMemory> {
        self.chain.chunks = Some(ChunkEncoder::new()?);
        Ok(())
    }

    /// Whether it goes chunked.
    pub(crate) fn is_chunked(&self) -> bool {
        self.chain.chunks.is_some()
    }

    /// Its line ends converted: the conversion stage added (`cr_lc_add`).
    pub(crate) fn convert_lines(&mut self) -> Result<(), OutOfMemory> {
        self.chain.lines = Some(try_box(LineConv::default())?);
        Ok(())
    }

    /// Sent as a mail's body to SMTP's `DATA`: its dots escaped and its
    /// end marked, above any conversion (`cr_eob_add`).
    pub(crate) fn end_as_mail(&mut self) -> Result<(), OutOfMemory> {
        self.chain.mail = Some(try_box(MailEnd::default())?);
        Ok(())
    }

    /// Its size as sent, where known (`Curl_creader_total_length`): a
    /// conversion or a mail's escaping makes it unknown.
    pub(crate) fn size(&self) -> Option<u64> {
        if self.chain.lines.is_some() || self.chain.mail.is_some() {
            return None;
        }
        self.upload.size()
    }

    /// The source.
    pub(crate) fn upload(&self) -> &Upload {
        &self.upload
    }

    pub(crate) fn upload_mut(&mut self) -> &mut Upload {
        &mut self.upload
    }

    /// Read into `dest`, which is not empty, through the stages
    /// (`Curl_client_read`); the chunk stage asks `trailers` for its
    /// trailers when the source ends.
    pub(crate) fn read<H: Host>(
        &mut self,
        cx: &mut StepCx<'_, H>,
        dest: &mut [u8],
        pausable: bool,
        trailers: Trailers<H>,
    ) -> Result<Readout, ErrorKind> {
        let Chain {
            chunks,
            mail,
            lines,
        } = &mut self.chain;
        let upload = &mut self.upload;
        let mut source = |cx: &mut StepCx<'_, H>, dest: &mut [u8]| match lines {
            Some(lines) => lines.read(cx, upload, dest, pausable),
            None => upload.read(cx, dest, pausable),
        };
        let mut below = |cx: &mut StepCx<'_, H>, dest: &mut [u8]| match mail {
            Some(mail) => mail.read(cx, &mut source, dest),
            None => source(cx, dest),
        };
        let Some(chunks) = chunks else {
            return below(cx, dest);
        };
        if let Some(room) = chunks.wants(dest.len()) {
            let got = below(cx, room)?;
            let read = Component::Read;
            if got.n > 0 {
                let n = got.n;
                trace::of(
                    cx,
                    read,
                    format_args!("http_chunk, made chunk of {n} bytes -> 0"),
                );
            }
            let end = if got.eos {
                // The application's trailers, if it gives any
                // (`add_last_chunk`).
                let asks = cx.easy().options().callbacks.trailer.is_some();
                let block = trailers(cx);
                match (&block, asks) {
                    (Ok(_), false) => {
                        trace::of(
                            cx,
                            read,
                            format_args!("http_chunk, added last, empty chunk"),
                        );
                    }
                    (_, _) => {
                        let code = trace::Code(block.as_ref().map(|_| ()).map_err(|&e| e));
                        trace::of(
                            cx,
                            read,
                            format_args!(
                                "http_chunk, added last chunk with trailers from client -> {code}"
                            ),
                        );
                    }
                }
                Some(block?)
            } else {
                None
            };
            chunks
                .got(got.n, end.as_deref())
                .map_err(|_| ErrorKind::OutOfMemory)?;
        }
        let (n, eos) = chunks.take(dest);
        Ok(Readout { n, eos })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `body` read through a mail's end in pieces of `cut` bytes, each
    /// given back into room for `room`.
    fn ended(body: &[u8], cut: usize, room: usize) -> Vec<u8> {
        let mut stage = MailEnd::default();
        let mut out = Vec::new();
        let mut dest = vec![0; room];
        let mut drain = |stage: &mut MailEnd, out: &mut Vec<u8>| {
            while !stage.held().is_empty() {
                let n = stage.give(&mut dest);
                out.extend_from_slice(&dest[..n]);
            }
        };
        for piece in body.chunks(cut) {
            if stage.passes(piece) {
                out.extend_from_slice(piece);
                continue;
            }
            stage.stuff(piece).unwrap();
            drain(&mut stage, &mut out);
        }
        stage.end().unwrap();
        drain(&mut stage, &mut out);
        out
    }

    /// What RFC 5321 makes of `body` (section 4.5.2), as C ends it: each
    /// dot that starts a line doubled, then a line of a single dot, after
    /// a CRLF unless the body is empty or ends with one.
    fn stuffed(body: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        let mut line_start = true;
        for (i, &b) in body.iter().enumerate() {
            if b == b'.' && line_start {
                out.push(b'.');
            }
            out.push(b);
            line_start = b == b'\n' && i > 0 && body[i - 1] == b'\r';
        }
        if !body.is_empty() && !body.ends_with(b"\r\n") {
            out.extend_from_slice(b"\r\n");
        }
        out.extend_from_slice(b".\r\n");
        out
    }

    #[test]
    fn a_mail_s_end_is_the_line_its_body_calls_for() {
        for (body, want) in [
            (&b""[..], &b".\r\n"[..]),
            (b"a", b"a\r\n.\r\n"),
            (b"a\r\n", b"a\r\n.\r\n"),
            (b"a\r", b"a\r\r\n.\r\n"),
            (b"a\n", b"a\n\r\n.\r\n"),
            (b".", b"..\r\n.\r\n"),
            (b"a\r\n.", b"a\r\n..\r\n.\r\n"),
            (b".a\r\n", b"..a\r\n.\r\n"),
            (b"\r\n.\r\n", b"\r\n..\r\n.\r\n"),
            (b"a\n.b", b"a\n.b\r\n.\r\n"),
            (b"a\r\n..b", b"a\r\n...b\r\n.\r\n"),
        ] {
            assert_eq!(ended(body, body.len().max(1), 64), want, "{body:?}");
        }
    }

    /// However the body comes and however little room each read has, its
    /// dots are escaped as RFC 5321 says and it ends as C ends it.
    #[test]
    fn a_mail_s_dots_are_escaped_however_its_reads_cut_it() {
        let bodies: [&[u8]; 7] = [
            b"line\r\n.dot\r\n..two\r\nend.\r\n.",
            b".\r\n.\r\n.\r\n",
            b"\r\r\n.\n.\r.\r\n.x",
            b"no line ends at all",
            b"\r\n\r\n\r\n",
            b"x\r\n.",
            b"x\r\n.\r",
        ];
        for body in bodies {
            let want = stuffed(body);
            for cut in 1..=body.len() {
                for room in [1, 2, 3, 7, 64] {
                    assert_eq!(ended(body, cut, room), want, "{body:?} {cut} {room}");
                }
            }
        }
    }
}
