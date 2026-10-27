//! A request over HTTP/3: its stream (`cf-ngtcp2.c`'s `h3_stream_ctx`).

use super::*;

/// A request's stream (`h3_stream_ctx`).
#[derive(Debug, Default)]
pub(super) struct H3Stream {}

impl Request {
    /// Send what of the request is in `out[sent..end]` (`cf_ngtcp2_send`).
    pub(super) fn h3_send<H: Host>(
        &mut self,
        cx: &mut StepCx<'_, H>,
        _: &mut ConnLease,
        _: usize,
        _: bool,
    ) -> Result<usize, ErrorKind> {
        let why = format_args!("HTTP/3 requests are not made yet");
        Err(trace::fail(cx, ErrorKind::Http3, why))
    }

    /// `read_some` over HTTP/3 (`cf_ngtcp2_recv`).
    pub(super) fn h3_read_some<H: Host>(
        &mut self,
        _: &mut StepCx<'_, H>,
        _: &mut ConnLease,
    ) -> Result<Read, ErrorKind> {
        Ok(Read::Waits)
    }

    /// The request is over (`h3_stream_done`).
    pub(super) fn h3_done<H: Host>(&mut self, _: &mut StepCx<'_, H>, _: &mut ConnLease) {}
}
