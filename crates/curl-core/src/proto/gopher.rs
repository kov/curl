//! Gopher (`lib/gopher.c`, RFC 1436) and, over TLS, gophers: a selector
//! made of the URL's path and query, sent on a connection of its own, and
//! the server's answer as the body, read until it closes the connection.

use curl_alloc::TryVec as _;

use super::base::peer_of;
use super::raw::Outgoing;
use super::xfer::Receive;
use super::{Connect, DoPhase, DoStep, ProtoStep, Waiting};
use crate::conn::io::Events;
use crate::conn::{ConnLease, Peer};
use crate::deliver::{Pause, Pipeline, Reach};
use crate::error::{ErrorKind, UrlErrorKind, url_error};
use crate::multi::Host;
use crate::multi::state::StepCx;
use crate::trace;
use crate::url::{GetOptions, Part, Url, decode_but_zero};

/// A Gopher transfer.
#[derive(Debug)]
pub(crate) struct Request {
    pub(super) base: super::base::RequestBase,
    /// The URL's path, as it is encoded, and its query, if it has one
    /// (`state.up.path`, `state.up.query`).
    path: Vec<u8>,
    query: Option<Vec<u8>>,
    /// The selector and its CRLF, once DO has made them.
    out: Outgoing,
    /// How much of `out` is the selector, which goes to the application
    /// as a header line as it is sent.
    selector: usize,
    answer: Receive,
}

/// The selector `path` and `query` ask for (`gopher_do`): none for `/`
/// and `/1`, else the path past its slash and item type, decoded, a zero
/// byte, CR or LF in it refused.
pub(crate) fn selector_of(path: &[u8], query: Option<&[u8]>) -> Result<Vec<u8>, Refused> {
    let mut whole = Vec::new();
    let oom = |_| Refused::OutOfMemory;
    whole.try_extend_from_slice(path).map_err(oom)?;
    if let Some(query) = query {
        whole.try_push(b'?').map_err(oom)?;
        whole.try_extend_from_slice(query).map_err(oom)?;
    }
    if whole.len() <= 2 {
        return Ok(Vec::new());
    }
    let selector = match decode_but_zero(&whole[2..]) {
        Ok(Some(s)) => s,
        Ok(None) => return Err(Refused::Malformed),
        Err(UrlErrorKind::OutOfMemory) => return Err(Refused::OutOfMemory),
        Err(_) => return Err(Refused::Malformed),
    };
    if selector.contains(&b'\r') || selector.contains(&b'\n') {
        return Err(Refused::LineEnd);
    }
    Ok(selector)
}

/// Why a URL makes no selector.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Refused {
    OutOfMemory,
    /// A zero byte in it, which C's decoding refuses.
    Malformed,
    /// A CR or LF in it, which would end the request early.
    LineEnd,
}

impl Request {
    /// A transfer of `url`, `gophers` if `secured`: its peer, its path and
    /// its query.
    pub(crate) fn new<H: Host>(
        url: &Url,
        secured: bool,
        first: Option<&Peer>,
        cx: &mut StepCx<'_, H>,
    ) -> Result<Request, ErrorKind> {
        let name: &[u8] = if secured { b"gophers" } else { b"gopher" };
        let peer = peer_of(url, name, cx)?;
        let gate = super::base::gate_of(first, &peer, cx);
        let encoded = GetOptions {
            url_encode: true,
            ..GetOptions::NONE
        };
        let path = url.get(Part::Path, encoded).map_err(url_error)?;
        let query = match url.get(Part::Query, GetOptions::NONE) {
            Ok(query) => Some(query),
            Err(UrlErrorKind::NoQuery) => None,
            Err(e) => return Err(url_error(e)),
        };
        Ok(Request {
            base: super::base::RequestBase {
                peer,
                pipeline: Pipeline::new(Reach::Network),
                credentials: None,
                gate,
            },
            path,
            query,
            out: Outgoing::default(),
            selector: 0,
            answer: Receive::default(),
        })
    }

    /// What the answer waits for on the connection's socket: it is read
    /// from DO on, and the transfer ends once it is read whole.
    pub(crate) fn interest(&self, pause: Pause) -> Events {
        if pause.recv_paused() {
            Events::NONE
        } else {
            Events::IN
        }
    }

    pub(crate) fn step<H: Host>(
        &mut self,
        cx: &mut StepCx<'_, H>,
        lease: &mut ConnLease,
    ) -> Result<ProtoStep, ErrorKind> {
        self.base.pipeline.flush(cx)?;
        self.answer.read(cx, lease, &mut self.base.pipeline)
    }

    /// Send the rest of the selector and its CRLF (`send_buf`), each piece
    /// of the selector that goes written to the application as a header
    /// line; once all have gone, the CRLF is written too, and the answer
    /// read.
    fn send<H: Host>(
        &mut self,
        cx: &mut StepCx<'_, H>,
        lease: &mut ConnLease,
    ) -> Result<bool, ErrorKind> {
        let selector = self.selector;
        let pipeline = &mut self.base.pipeline;
        let sent = self.out.send(cx, lease, &mut |cx, at, piece| {
            let header = &piece[..selector.saturating_sub(at).min(piece.len())];
            // An empty selector writes nothing, as C's loop never runs.
            if header.is_empty() {
                return Ok(());
            }
            pipeline.protocol_header(cx, header)
        });
        match sent {
            Ok(true) => {}
            Ok(false) => return Ok(false),
            Err(e) => {
                return Err(trace::fail(
                    cx,
                    e,
                    format_args!("Failed sending Gopher request"),
                ));
            }
        }
        self.base.pipeline.protocol_header(cx, b"\r\n")?;
        self.answer.start_to_end(cx);
        Ok(true)
    }
}

impl super::Phases for Request {
    /// Gopher has no connect of its own; gophers's TLS is the
    /// connection's.
    fn connect<H: Host>(
        &mut self,
        _: &mut StepCx<'_, H>,
        _: &mut ConnLease,
    ) -> Result<Connect, ErrorKind> {
        Ok(Connect::Done)
    }

    /// Make the selector and send it, in DO, and what of it the
    /// connection did not take in DOING: C sends it all in DO, waiting on
    /// the socket as it must.
    fn make<H: Host>(
        &mut self,
        cx: &mut StepCx<'_, H>,
        lease: &mut ConnLease,
        asked: DoPhase,
    ) -> Result<DoStep, ErrorKind> {
        if asked == DoPhase::Do {
            let selector = match selector_of(&self.path, self.query.as_deref()) {
                Ok(selector) => selector,
                Err(Refused::OutOfMemory) => return Err(ErrorKind::OutOfMemory),
                Err(Refused::Malformed) => return Err(ErrorKind::UrlMalformat),
                Err(Refused::LineEnd) => {
                    return Err(trace::fail(
                        cx,
                        ErrorKind::UrlMalformat,
                        format_args!("Bad gopher selector, CR or LF not allowed"),
                    ));
                }
            };
            self.selector = selector.len();
            self.out = Outgoing::of(&[&selector, b"\r\n"])?;
        }
        Ok(if self.send(cx, lease)? {
            DoStep::Did
        } else {
            DoStep::Doing
        })
    }

    fn waits(&self, phase: Waiting, _: Option<&crate::conn::line::LineConn>) -> Events {
        phase.c_default()
    }
}

#[cfg(test)]
mod tests;
