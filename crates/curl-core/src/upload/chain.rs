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
    /// `CURL_CR_CONTENT_ENCODE`: each lone LF sent as CRLF
    /// (`cr-lineconv`); boxed, as few bodies are converted and every
    /// transfer's state holds its body inline.
    lines: Option<Box<LineConv>>,
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

    /// Its size as sent, where known (`Curl_creader_total_length`): a
    /// conversion makes it unknown.
    pub(crate) fn size(&self) -> Option<u64> {
        match self.chain.lines {
            Some(_) => None,
            None => self.upload.size(),
        }
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
        let Chain { chunks, lines } = &mut self.chain;
        let upload = &mut self.upload;
        let mut below = |cx: &mut StepCx<'_, H>, dest: &mut [u8]| match lines {
            Some(lines) => lines.read(cx, upload, dest, pausable),
            None => upload.read(cx, dest, pausable),
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
