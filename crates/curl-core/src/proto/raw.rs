//! What DICT and Gopher share: a request sent whole as the transfer's
//! DO, and its answer, the transfer's body, read until the server closes
//! the connection (C's `Curl_xfer_send` loop; `xfer::Receive` reads it).

use curl_alloc::TryVec as _;

use crate::conn::io::Recv;
use crate::conn::{ConnLease, RecvFailed};
use crate::error::ErrorKind;
use crate::multi::Host;
use crate::multi::state::StepCx;
use crate::trace;
use curl_os::net::Sent;

/// What is told of each piece of a request that goes: where it starts in
/// the request, and its bytes.
pub(crate) type Each<'a, 'c, H> =
    dyn FnMut(&mut StepCx<'c, H>, usize, &[u8]) -> Result<(), ErrorKind> + 'a;

/// A request on its way out: its bytes, and how many have gone.
#[derive(Debug, Default)]
pub(crate) struct Outgoing {
    bytes: Vec<u8>,
    sent: usize,
}

impl Outgoing {
    /// The request `parts` make, none of it sent yet.
    pub(crate) fn of(parts: &[&[u8]]) -> Result<Outgoing, ErrorKind> {
        let mut bytes = Vec::new();
        for part in parts {
            bytes
                .try_extend_from_slice(part)
                .map_err(|_| ErrorKind::OutOfMemory)?;
        }
        Ok(Outgoing { bytes, sent: 0 })
    }

    /// Whether all of it has gone.
    pub(crate) fn is_sent(&self) -> bool {
        self.sent == self.bytes.len()
    }

    /// Send what the connection takes of the rest now, `each` told of
    /// every send, where it starts in the request and the bytes that went
    /// (none if the connection would block). Whether all of it has gone.
    /// A failing send fails it.
    pub(crate) fn send<'c, H: Host>(
        &mut self,
        cx: &mut StepCx<'c, H>,
        lease: &mut ConnLease,
        each: &mut Each<'_, 'c, H>,
    ) -> Result<bool, ErrorKind> {
        while !self.is_sent() {
            let at = self.sent;
            let n = xfer_send(cx, lease, &self.bytes[at..])?;
            self.sent += n;
            each(cx, at, &self.bytes[at..at + n])?;
            if n == 0 {
                return Ok(false);
            }
        }
        Ok(true)
    }
}

/// Send what the connection takes of `bytes` now, none if it would block,
/// said in the debug build's trace (`Curl_xfer_send`).
pub(crate) fn xfer_send<H: Host>(
    cx: &mut StepCx<'_, H>,
    lease: &mut ConnLease,
    bytes: &[u8],
) -> Result<usize, ErrorKind> {
    let (n, failed) = match lease.get().send(cx, bytes) {
        Ok(Sent::Bytes(n)) => (n.get(), None),
        Ok(Sent::WouldBlock) => (0, None),
        Err(_) => (0, Some(ErrorKind::SendError)),
    };
    let code = failed.map_or(0, ErrorKind::number);
    let len = bytes.len();
    trace::debug_info(
        cx,
        format_args!("Curl_xfer_send(len={len}, eos=0) -> {code}, {n}"),
    );
    match failed {
        Some(kind) => Err(kind),
        None => Ok(n),
    }
}

/// What a read of the connection got.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Got {
    /// This many bytes.
    Data(usize),
    /// The end: the server closed the connection.
    Eof,
    /// Nothing yet (`CURLE_AGAIN`).
    Again,
}

/// Read what the connection has into `out`, no more than it holds nor
/// than a read of the transfer's takes (`Curl_xfer_recv`): a failing read
/// fails the transfer, said as the socket says it.
pub(crate) fn xfer_recv<H: Host>(
    cx: &mut StepCx<'_, H>,
    lease: &mut ConnLease,
    out: &mut [u8],
) -> Result<Got, ErrorKind> {
    let max = cx.easy().options().limits.buffer_size.get().min(out.len());
    let said = cx.easy().report().reasons();
    // Read in the multi's buffer, and copied out from there.
    let got = crate::conn::buf::lending(cx, lease, |cx, lease| {
        let got = lease.get().recv(cx, max);
        got.map(|recv| match recv {
            Recv::Data(_) => {
                let rx = lease.get().rx_mut();
                let n = rx.filled().len().min(out.len());
                out[..n].copy_from_slice(&rx.filled()[..n]);
                rx.consume(n);
                Got::Data(n)
            }
            Recv::Eof => Got::Eof,
            Recv::WouldBlock => Got::Again,
        })
    })
    .map_err(|_| ErrorKind::OutOfMemory)?;
    match got {
        Ok(got) => Ok(got),
        Err(RecvFailed::OutOfMemory) => Err(ErrorKind::OutOfMemory),
        Err(RecvFailed::Os(_)) if cx.easy().report().reasons() > said => Err(ErrorKind::RecvError),
        Err(RecvFailed::Os(e)) => {
            let why = curl_os::error::ErrorText::of(&e);
            Err(trace::fail_with(
                cx,
                ErrorKind::RecvError,
                &[b"Recv failure: ", why.as_bytes()],
            ))
        }
    }
}

#[cfg(test)]
pub(crate) mod wire;
