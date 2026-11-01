//! A WebSocket over an HTTP/1.1 request: the 101 that switches its
//! connection (`Curl_ws_accept`), and what its frames go out on while a
//! transfer runs, its own step's or its handlers' (`Curl_xfer_send`,
//! `ws_send_raw_blocking`).

use std::fmt;
use std::time::Duration;

use super::{Body, Reading, Request, Sending, Stage};
use crate::components::Component;
use crate::conn::ConnLease;
use crate::conn::io::Sent;
use crate::conn::line::LineConn;
use crate::conn::mux::Carrier;
use crate::error::ErrorKind;
use crate::multi::Host;
use crate::multi::state::StepCx;
use crate::multi::timers::TimeLeft;
use crate::proto::ws::{Said, Wire, WsConn};
use crate::trace;
use crate::upload::{self, Upload, chain};
use crate::ws::{FrameLen, Received, SendFlags, Sent as WsSent};

/// What a WebSocket says, on the transfer's trace.
pub(crate) struct StepSaid<'w, 'c, H: Host>(pub(crate) &'w mut StepCx<'c, H>);

impl<H: Host> Said for StepSaid<'_, '_, H> {
    fn ws(&mut self, args: fmt::Arguments<'_>) {
        trace::of(self.0, Component::Ws, args);
    }

    fn info(&mut self, args: fmt::Arguments<'_>) {
        trace::info(self.0, args);
    }

    fn fail(&mut self, kind: ErrorKind, args: fmt::Arguments<'_>) -> ErrorKind {
        trace::fail(self.0, kind, args)
    }
}

/// The transfer's connection, as a WebSocket's frames go out on it while
/// the transfer runs: each send as the transfer's (`Curl_xfer_send`).
pub(crate) struct StepWire<'w, 'c, H: Host> {
    pub(crate) cx: &'w mut StepCx<'c, H>,
    pub(crate) carrier: Carrier<'w>,
}

impl<H: Host> Said for StepWire<'_, '_, H> {
    fn ws(&mut self, args: fmt::Arguments<'_>) {
        trace::of(self.cx, Component::Ws, args);
    }

    fn info(&mut self, args: fmt::Arguments<'_>) {
        trace::info(self.cx, args);
    }

    fn fail(&mut self, kind: ErrorKind, args: fmt::Arguments<'_>) -> ErrorKind {
        trace::fail(self.cx, kind, args)
    }
}

impl<H: Host> Wire for StepWire<'_, '_, H> {
    fn random(&mut self, out: &mut [u8]) -> Result<(), ErrorKind> {
        self.cx
            .easy()
            .libraries()
            .random(out)
            .map_err(|_| ErrorKind::FailedInit)
    }

    fn send(&mut self, bytes: &[u8]) -> Result<usize, ErrorKind> {
        let sent = self.carrier.send(self.cx, bytes);
        let (n, failed) = match sent {
            Ok(Sent::Bytes(n)) => (n.get(), None),
            Ok(_) => (0, None),
            Err(_) => (0, Some(ErrorKind::SendError)),
        };
        if n > 0 {
            self.cx.report_mut().sizes_mut().request += n as u64;
        }
        let code = failed.map_or(0, ErrorKind::number);
        let len = bytes.len();
        trace::debug_info(
            self.cx,
            format_args!("Curl_xfer_send(len={len}, eos=0) -> {code}, {n}"),
        );
        match failed {
            Some(kind) => Err(kind),
            None => Ok(n),
        }
    }

    fn recv(&mut self, buf: &mut [u8]) -> Result<Option<usize>, ErrorKind> {
        match self.carrier.recv_into(self.cx, buf) {
            Ok(got) => Ok(got),
            Err(crate::conn::RecvFailed::OutOfMemory) => Err(ErrorKind::OutOfMemory),
            Err(crate::conn::RecvFailed::Os(_)) => Err(ErrorKind::RecvError),
        }
    }

    fn send_all(&mut self, mut bytes: &[u8]) -> Result<(), ErrorKind> {
        while !bytes.is_empty() {
            let n = self.send(bytes)?;
            bytes = &bytes[n..];
            if bytes.is_empty() {
                break;
            }
            let left = bytes.len();
            self.ws(format_args!(
                "ws_send_raw_blocking() partial, {left} left to send"
            ));
            let wait = match self.cx.time_left() {
                TimeLeft::Expired(_) => {
                    let why = format_args!("[WS] Timeout waiting for socket becoming writable");
                    return Err(self.fail(ErrorKind::SendError, why));
                }
                TimeLeft::Remaining(left) => left,
                // No limit waits half a second at a time.
                TimeLeft::Unlimited => Duration::from_millis(500),
            };
            if self.carrier.wait_writable(wait).is_err() {
                let why = format_args!("[WS] Error while waiting for socket becoming writable");
                return Err(self.fail(ErrorKind::SendError, why));
            }
        }
        Ok(())
    }
}

/// A WebSocket's connection's frames' state and what they go out on, as
/// the step has it lent.
pub(crate) fn lent<'w, 'c, H: Host>(
    cx: &'w mut StepCx<'c, H>,
    conn: &'w mut crate::conn::WsLend<'_>,
) -> (&'w mut WsConn, StepWire<'w, 'c, H>) {
    let (ws, carrier) = conn.parts();
    (ws, StepWire { cx, carrier })
}

/// The application sends on the transfer's WebSocket from inside its
/// handler, the connection lent (`curl_ws_send`): its sends wait.
pub(crate) fn lent_send<H: Host>(
    cx: &mut StepCx<'_, H>,
    bytes: &[u8],
    len: FrameLen,
    flags: SendFlags,
) -> Result<WsSent, ErrorKind> {
    let raw = cx.easy().options().ws.raw;
    let sent = cx.with_ws_conn(|cx, conn| {
        let (ws, mut wire) = lent(cx, conn);
        crate::proto::ws::api_send(ws, &mut wire, raw, bytes, len, flags, true)
    });
    sent.unwrap_or_else(|| {
        let why = format_args!("[WS] Not a websocket transfer");
        Err(trace::fail(cx, ErrorKind::SendError, why))
    })
}

/// The application gets ready for a send on the transfer's WebSocket from
/// inside its handler (`Call::Prepare`): what waits to go waits for the
/// connection.
pub(crate) fn lent_prepare<H: Host>(
    cx: &mut StepCx<'_, H>,
) -> Result<crate::ws::Prepared, ErrorKind> {
    let prepared = cx.with_ws_conn(|cx, conn| {
        let (ws, mut wire) = lent(cx, conn);
        crate::proto::ws::api_prepare(ws, &mut wire, true)
    });
    prepared.unwrap_or_else(|| {
        let why = format_args!("[WS] Not a websocket transfer");
        Err(trace::fail(cx, ErrorKind::SendError, why))
    })
}

/// The application sends more of the frame under way on the transfer's
/// WebSocket from inside its handler (`Call::SendMore`): its sends wait.
pub(crate) fn lent_send_more<H: Host>(
    cx: &mut StepCx<'_, H>,
    bytes: &[u8],
) -> Result<WsSent, ErrorKind> {
    let sent = cx.with_ws_conn(|cx, conn| {
        let (ws, mut wire) = lent(cx, conn);
        crate::proto::ws::api_send_more(ws, &mut wire, bytes, true)
    });
    sent.unwrap_or_else(|| {
        let why = format_args!("[WS] Not a websocket transfer");
        Err(trace::fail(cx, ErrorKind::SendError, why))
    })
}

/// The application starts a frame on the transfer's WebSocket from
/// inside its handler (`curl_ws_start_frame`).
pub(crate) fn lent_start_frame<H: Host>(
    cx: &mut StepCx<'_, H>,
    flags: SendFlags,
    len: u64,
) -> Result<(), ErrorKind> {
    let raw = cx.easy().options().ws.raw;
    let started = cx.with_ws_conn(|cx, conn| {
        let (ws, mut wire) = lent(cx, conn);
        crate::proto::ws::api_start_frame(ws, &mut wire, raw, flags, len)
    });
    started.unwrap_or_else(|| {
        let why = format_args!("[WS] Not a websocket transfer");
        Err(trace::fail(cx, ErrorKind::SendError, why))
    })
}

/// The application receives on the transfer's WebSocket from inside its
/// handler (`curl_ws_recv`).
pub(crate) fn lent_recv<H: Host>(
    cx: &mut StepCx<'_, H>,
    buf: &mut [u8],
) -> Result<Received, ErrorKind> {
    let options = cx.easy().options().ws;
    let got = cx.with_ws_conn(|cx, conn| {
        let (ws, mut wire) = lent(cx, conn);
        crate::proto::ws::api_recv(ws, &mut wire, buf, options.raw, options.auto_pong(), true)
    });
    got.unwrap_or_else(|| {
        let why = format_args!("[WS] connection is not setup for websocket");
        Err(trace::fail(cx, ErrorKind::BadFunctionArgument, why))
    })
}

/// The WebSocket of the connection lent to the step.
pub(crate) fn ws_of<'s, H: Host>(cx: &'s mut StepCx<'_, H>) -> &'s mut WsConn {
    cx.lent_ws()
        .expect("a WebSocket's frames are worked with its connection lent")
}

impl Request {
    /// The upload starts over, once switched, as a WebSocket's: read to
    /// its end whatever its size, as binary frames unless `raw`, its
    /// frames' bytes sent as the transfer's (`Curl_ws_accept`).
    fn ws_upload<H: Host>(
        &mut self,
        cx: &mut StepCx<'_, H>,
        lease: &mut ConnLease,
        raw: bool,
    ) -> Result<(), ErrorKind> {
        let mut upload = Upload::open(cx)?;
        upload.read_to_end();
        upload.trace_set(cx);
        *cx.readers_mut() = upload.pausing().map(|client| upload::Readers {
            chunked: false,
            exp100: false,
            mail: false,
            lines: false,
            client,
        });
        let mut body = chain::Body::new(upload);
        if !raw {
            body.encode_websocket();
            lease
                .get()
                .ws_mut()
                .expect("switched to a WebSocket")
                .0
                .using_reader = true;
        }
        self.body = Some(body);
        let room = cx.easy().options().limits.upload_buffer.get();
        self.out.clear();
        self.out
            .try_reserve_exact(room)
            .map_err(|_| ErrorKind::OutOfMemory)?;
        super::zeros(&mut self.out, room).map_err(|_| ErrorKind::OutOfMemory)?;
        self.filled = 0;
        self.sent = 0;
        self.body_sent = 0;
        self.outgoing = Sending::Body(Reading {
            eos_read: false,
            announced: false,
        });
        Ok(())
    }

    /// A 101 took up the request's WebSocket upgrade: the connection
    /// speaks WebSocket from here, `rest` the first of its frames
    /// (`Curl_ws_accept`). How many of `rest`'s bytes are left on the
    /// connection, unread, for the application to receive.
    pub(super) fn ws_upgraded<H: Host>(
        &mut self,
        cx: &mut StepCx<'_, H>,
        lease: &mut ConnLease,
        rest: &[u8],
    ) -> Result<usize, ErrorKind> {
        trace::info(cx, format_args!("Received 101, Switching to WebSocket"));
        self.upgrade = None;
        let ws = WsConn::new(&mut StepSaid(cx)).map_err(|_| ErrorKind::OutOfMemory)?;
        let ws = curl_alloc::try_box(LineConn::Ws(ws)).map_err(|_| ErrorKind::OutOfMemory)?;
        lease.get().switch_to_ws(ws);
        let accepted = self.ws_accept(cx, lease, rest);
        match accepted {
            Ok(_) => {
                let mode = if cx.easy().options().connect_only.reserves() {
                    "connect-only"
                } else {
                    "callback"
                };
                trace::of(
                    cx,
                    Component::Ws,
                    format_args!("websocket established, {mode} mode"),
                );
            }
            Err(kind) => {
                let code = kind.number();
                trace::of(
                    cx,
                    Component::Ws,
                    format_args!("Curl_ws_accept() failed -> {code}"),
                );
            }
        }
        accepted
    }

    fn ws_accept<H: Host>(
        &mut self,
        cx: &mut StepCx<'_, H>,
        lease: &mut ConnLease,
        rest: &[u8],
    ) -> Result<usize, ErrorKind> {
        // C's client does not check the server's `Sec-WebSocket-Accept`.
        trace::info(cx, format_args!("[WS] Received 101, switch to WebSocket"));
        let raw = cx.easy().options().ws.raw;
        self.pipeline.decode_websocket(raw)?;
        if cx.easy().options().connect_only.reserves() {
            // What came after the 101 waits on the connection for the
            // application's receives, and the transfer reads no more.
            self.stage = Stage::Done;
            return Ok(rest.len());
        }
        self.stage = Stage::Body(Body::WebSocket);
        // Never reused: a WebSocket's connection ends with it.
        lease.get().mark_close();
        if self.websocket.is_some_and(|w| w.uploads) {
            trace::of(
                cx,
                Component::Ws,
                format_args!("UPLOAD set, add ws-encode reader"),
            );
            self.ws_upload(cx, lease, raw)?;
        }
        if !rest.is_empty() {
            let conn = lease
                .get()
                .ws_lend()
                .expect("a WebSocket's connection speaks it");
            cx.lending_ws(conn, |cx| self.pipeline.body(cx, rest))?;
        }
        Ok(0)
    }
}
