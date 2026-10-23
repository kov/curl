//! What a request reads of its body: the source, then the stages C stacks
//! above its client reader (`Curl_creader_add`), each with its own buffer.

use curl_alloc::OutOfMemory;

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
        let Some(chunks) = &mut self.chain.chunks else {
            return self.upload.read(cx, dest, pausable);
        };
        if let Some(room) = chunks.wants(dest.len()) {
            let got = self.upload.read(cx, room, pausable)?;
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
