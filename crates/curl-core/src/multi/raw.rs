//! What a handle does itself with the connection its transfer only made
//! (`CURLOPT_CONNECT_ONLY`): bytes sent and received on it
//! (`curl_easy_send`, `curl_easy_recv`) and its socket told
//! (`CURLINFO_ACTIVESOCKET`). The connection stays reserved for the handle
//! in the pool it was made in (`Place::Reserved`), which the handle names
//! by its last connection. Also what a handle does with its pool's
//! connections between transfers: keep them alive (`curl_easy_upkeep`).

use std::fmt;

use super::{Host, Multi, TransferId};
use crate::conn::RecvFailed;
use crate::conn::io::{Recv, Sent, SocketKey};
use crate::conn::layer::LayerCx;
use crate::conn::pool::Pool;
use crate::easy::Easy;
use crate::error::ErrorKind;
use crate::share::{Kind, watched};
use crate::time::Instant;

/// What a raw send or receive moved: bytes, none at a receive meaning the
/// peer closed its side; or nothing for now (`CURLE_AGAIN`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RawIo {
    Bytes(usize),
    WouldBlock,
}

/// A raw send or receive.
enum Way<'a> {
    Recv(&'a mut [u8]),
    Send(&'a [u8]),
}

/// The context of a raw send or receive: no transfer runs, so nothing is
/// traced; a failure is kept in the handle's report and told to its
/// error sink, as C's `failf` keeps it.
struct RawCx<'a> {
    now: Instant,
    easy: &'a mut Easy,
}

impl LayerCx for RawCx<'_> {
    fn now(&self) -> Instant {
        self.now
    }

    fn trace(&mut self) -> Option<&mut dyn crate::conn::layer::Trace> {
        None
    }

    fn failures(&mut self) -> Option<&mut dyn crate::conn::layer::Failures> {
        Some(self)
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
        None
    }
}

impl crate::conn::layer::Failures for RawCx<'_> {
    fn keep(&mut self, kind: ErrorKind, why: fmt::Arguments<'_>) -> ErrorKind {
        fail(self.easy, kind, crate::trace::reason(why))
    }

    fn keep_with(&mut self, kind: ErrorKind, parts: &[&[u8]]) -> ErrorKind {
        fail(self.easy, kind, crate::trace::reason_with(parts))
    }

    fn keep_errno(&mut self, e: &std::io::Error) {
        self.easy.report_mut().socket_failed(e);
    }
}

/// Keep `why` as the reason the handle failed, if it is the first, and
/// tell the application's error sink (`failf` outside a transfer).
fn fail(easy: &mut Easy, kind: ErrorKind, reason: crate::trace::Reason) -> ErrorKind {
    let detail = reason.bytes();
    let first = easy.report().unsaid();
    easy.report_mut().record_failure(detail);
    if first && let Some(sink) = easy.options().callbacks.failure.clone() {
        sink.write(detail);
    }
    kind
}

/// Run `f` on the pool `easy`'s connections are in: its share's, if that
/// keeps connections, under its lock; else `own`, the multi's, if there
/// is one.
fn in_pool<R>(
    own: Option<&mut Pool>,
    easy: &mut Easy,
    f: impl FnOnce(Option<&mut Pool>, &mut Easy) -> R,
) -> R {
    let share = easy.share().filter(|s| s.keeps(Kind::Connections)).cloned();
    match share {
        Some(share) => {
            let watch = easy.share_watch.clone();
            watched(watch.as_deref(), &share, Kind::Connections, || {
                let mut pool = share.pool();
                f(Some(&mut pool), easy)
            })
        }
        None => f(own, easy),
    }
}

/// A raw send or receive on the connection `easy` reserved, in `pool`
/// (`curl_easy_send`, `curl_easy_recv`): refused for a handle that does
/// not only connect, or whose connection is gone, which it then forgets
/// (`easy_connection`, `Curl_cpool_get_last_conn`).
fn raw(
    pool: Option<&mut Pool>,
    easy: &mut Easy,
    now: Instant,
    way: Way<'_>,
) -> Result<RawIo, ErrorKind> {
    if !easy.options().connect_only.reserves() {
        let why = format_args!("CONNECT_ONLY is required");
        return Err(fail(
            easy,
            ErrorKind::UnsupportedProtocol,
            crate::trace::reason(why),
        ));
    }
    let last = easy.last_conn;
    let conn = last.and_then(|l| pool?.reserved_mut(l.id));
    let Some(conn) = conn else {
        // Forgotten as it is looked for, so C names it as none.
        easy.last_conn = None;
        easy.report_mut().set_conn(None);
        let why = format_args!("Failed to get last socket used for connection #-1");
        return Err(fail(
            easy,
            ErrorKind::UnsupportedProtocol,
            crate::trace::reason(why),
        ));
    };
    if let Some(l) = easy.last_conn.as_mut() {
        l.used = true;
    }
    let mut cx = RawCx { now, easy };
    match way {
        Way::Recv([]) => Ok(RawIo::Bytes(0)),
        Way::Recv(buf) => match conn.recv(&mut cx, buf.len()) {
            Ok(Recv::Data(_)) => {
                let rx = conn.rx_mut();
                let n = rx.filled().len().min(buf.len());
                buf[..n].copy_from_slice(&rx.filled()[..n]);
                rx.consume(n);
                Ok(RawIo::Bytes(n))
            }
            Ok(Recv::Eof) => {
                // Closed by the peer: not reused.
                conn.mark_close();
                Ok(RawIo::Bytes(0))
            }
            Ok(Recv::WouldBlock) => Ok(RawIo::WouldBlock),
            Err(RecvFailed::OutOfMemory) => Err(ErrorKind::OutOfMemory),
            Err(RecvFailed::Os(_)) => Err(ErrorKind::RecvError),
        },
        Way::Send([]) => Ok(RawIo::Bytes(0)),
        // Any failure but a wait is a send's (`Curl_senddata`).
        Way::Send(bytes) => match conn.send(&mut cx, bytes) {
            Ok(Sent::Bytes(n)) => Ok(RawIo::Bytes(n.get())),
            Ok(Sent::WouldBlock) => Ok(RawIo::WouldBlock),
            Err(_) => Err(ErrorKind::SendError),
        },
    }
}

impl<H: Host> Multi<H> {
    /// Receive into `buf` on the connection transfer `id` only made, once
    /// it is done (`curl_easy_recv`). `None` if `id` is not in this multi.
    pub fn recv_raw(&mut self, id: TransferId, buf: &mut [u8]) -> Option<Result<RawIo, ErrorKind>> {
        self.raw_on(id, Way::Recv(buf))
    }

    /// Send from `bytes` on the connection transfer `id` only made, once
    /// it is done (`curl_easy_send`). `None` if `id` is not in this multi.
    pub fn send_raw(&mut self, id: TransferId, bytes: &[u8]) -> Option<Result<RawIo, ErrorKind>> {
        self.raw_on(id, Way::Send(bytes))
    }

    fn raw_on(&mut self, id: TransferId, way: Way<'_>) -> Option<Result<RawIo, ErrorKind>> {
        let now = self.clock.now();
        let easy = &mut self.slots.get_mut(id)?.easy;
        Some(in_pool(Some(&mut self.caches.pool), easy, |pool, easy| {
            raw(pool, easy, now, way)
        }))
    }

    /// The socket of the connection transfer `id` had last, if it is
    /// still open: the one it holds, or one its pool keeps
    /// (`CURLINFO_ACTIVESOCKET`, `Curl_getconnectinfo`). `None` if `id` is
    /// not in this multi.
    pub fn active_socket(&mut self, id: TransferId) -> Option<Option<SocketKey>> {
        let slot = self.slots.get_mut(id)?;
        if let Some(lease) = slot.run.as_ref().and_then(|r| r.state.lease()) {
            let slot = self.caches.pool.slot_of(lease);
            return Some(slot.and_then(|s| s.sockets().next()).map(|s| s.key()));
        }
        Some(in_pool(
            Some(&mut self.caches.pool),
            &mut slot.easy,
            pool_socket,
        ))
    }

    /// As `recv_raw`, for `easy`, not added, whose transfers this multi
    /// ran.
    pub fn recv_raw_for(&mut self, easy: &mut Easy, buf: &mut [u8]) -> Result<RawIo, ErrorKind> {
        let now = self.clock.now();
        in_pool(Some(&mut self.caches.pool), easy, |pool, easy| {
            raw(pool, easy, now, Way::Recv(buf))
        })
    }

    /// As `send_raw`, for `easy`, not added, whose transfers this multi
    /// ran.
    pub fn send_raw_for(&mut self, easy: &mut Easy, bytes: &[u8]) -> Result<RawIo, ErrorKind> {
        let now = self.clock.now();
        in_pool(Some(&mut self.caches.pool), easy, |pool, easy| {
            raw(pool, easy, now, Way::Send(bytes))
        })
    }

    /// As `active_socket`, for `easy`, not added, whose transfers this
    /// multi ran.
    pub fn active_socket_for(&mut self, easy: &mut Easy) -> Option<SocketKey> {
        in_pool(Some(&mut self.caches.pool), easy, pool_socket)
    }
}

/// The socket of `easy`'s last connection in `pool`, if it holds it; a
/// connection gone is forgotten (`Curl_cpool_get_last_conn`).
fn pool_socket(pool: Option<&mut Pool>, easy: &mut Easy) -> Option<SocketKey> {
    let last = easy.last_conn?;
    let socket = pool.and_then(|p| p.socket(last.id));
    if socket.is_none() {
        easy.last_conn = None;
        easy.report_mut().set_conn(None);
    }
    socket
}

/// Now, for a raw send or receive on a share's connection by a handle
/// that has no multi, whose layers keep no time but their own.
fn no_clock() -> Instant {
    use crate::time::Clock as _;
    crate::time::SystemClock::new().now()
}

impl Easy {
    /// Keep alive the connections of the handle's pool that have gone its
    /// upkeep interval without (`curl_easy_upkeep`): an HTTP/2 connection
    /// is sent a PING, others nothing. The pool is its share's, if that
    /// keeps connections, else the one `perform` keeps; a handle with
    /// neither has none to keep.
    pub fn upkeep(&mut self) -> Result<(), curl_alloc::OutOfMemory> {
        match self.private.take() {
            Some(mut private) => {
                let crate::easy::Private { multi, events } = &mut *private;
                let kept = match events {
                    Some(table) => multi.upkeep_for(self, table),
                    None => multi.upkeep_for(self, &mut super::NoEvents),
                };
                self.private = Some(private);
                kept
            }
            None => {
                if let Some(share) = self.share().filter(|s| s.keeps(Kind::Connections)) {
                    let watch = self.share_watch.as_deref();
                    let interval = self.options().limits.reuse.upkeep.0;
                    watched(watch, share, Kind::Connections, || {
                        share.upkeep(interval, no_clock());
                    });
                }
                Ok(())
            }
        }
    }

    /// Receive into `buf` on the connection the handle's last transfer
    /// only made (`curl_easy_recv`), once `perform` is done.
    pub fn recv_raw(&mut self, buf: &mut [u8]) -> Result<RawIo, ErrorKind> {
        match self.private.take() {
            Some(mut private) => {
                let got = private.multi.recv_raw_for(self, buf);
                self.private = Some(private);
                got
            }
            None => in_pool(None, self, |pool, easy| {
                raw(pool, easy, no_clock(), Way::Recv(buf))
            }),
        }
    }

    /// Send from `bytes` on the connection the handle's last transfer
    /// only made (`curl_easy_send`), once `perform` is done.
    pub fn send_raw(&mut self, bytes: &[u8]) -> Result<RawIo, ErrorKind> {
        match self.private.take() {
            Some(mut private) => {
                let sent = private.multi.send_raw_for(self, bytes);
                self.private = Some(private);
                sent
            }
            None => in_pool(None, self, |pool, easy| {
                raw(pool, easy, no_clock(), Way::Send(bytes))
            }),
        }
    }

    /// The socket of the connection the handle's last transfer had, if
    /// its pool still keeps it open (`CURLINFO_ACTIVESOCKET`).
    pub fn active_socket(&mut self) -> Option<SocketKey> {
        match self.private.take() {
            Some(mut private) => {
                let socket = private.multi.active_socket_for(self);
                self.private = Some(private);
                socket
            }
            None => in_pool(None, self, pool_socket),
        }
    }
}

/// The connection a handle's transfer only made, as its WebSocket's
/// frames go out on it and come in from it: no transfer runs, so nothing
/// is traced (`Curl_senddata`, `Curl_easy_recv`).
struct RawWire<'a> {
    cx: RawCx<'a>,
    carrier: crate::conn::mux::Carrier<'a>,
}

impl crate::proto::ws::Said for RawWire<'_> {
    fn ws(&mut self, _: fmt::Arguments<'_>) {}

    fn info(&mut self, _: fmt::Arguments<'_>) {}

    fn fail(&mut self, kind: ErrorKind, why: fmt::Arguments<'_>) -> ErrorKind {
        fail(self.cx.easy, kind, crate::trace::reason(why))
    }
}

impl crate::proto::ws::Wire for RawWire<'_> {
    fn random(&mut self, out: &mut [u8]) -> Result<(), ErrorKind> {
        self.cx
            .easy
            .libraries()
            .random(out)
            .map_err(|_| ErrorKind::FailedInit)
    }

    fn send(&mut self, bytes: &[u8]) -> Result<usize, ErrorKind> {
        // Any failure but a wait is a send's (`Curl_senddata`).
        match self.carrier.send(&mut self.cx, bytes) {
            Ok(Sent::Bytes(n)) => Ok(n.get()),
            Ok(_) => Ok(0),
            Err(_) => Err(ErrorKind::SendError),
        }
    }

    // Only a send from inside a callback waits for the connection, and a
    // connection the transfer only made is reached from outside one.
    fn send_all(&mut self, _: &[u8]) -> Result<(), ErrorKind> {
        unreachable!("a connection only made is sent on without waiting")
    }

    fn recv(&mut self, buf: &mut [u8]) -> Result<Option<usize>, ErrorKind> {
        match self.carrier.recv_into(&mut self.cx, buf) {
            Ok(got) => Ok(got),
            Err(RecvFailed::OutOfMemory) => Err(ErrorKind::OutOfMemory),
            Err(RecvFailed::Os(_)) => Err(ErrorKind::RecvError),
        }
    }
}

/// A call on the WebSocket of the connection `easy` reserved, in `pool`
/// (`curl_ws_recv`, `curl_ws_send`, `curl_ws_start_frame` once the
/// transfer is done): refused for a handle that does not only connect,
/// whose connection is gone, or that is not a WebSocket's.
fn ws(
    pool: Option<&mut Pool>,
    easy: &mut Easy,
    now: Instant,
    call: crate::ws::Call<'_>,
) -> Result<crate::ws::Answer, ErrorKind> {
    use crate::ws::{Answer, Call};
    let options = easy.options().ws;
    let refuse = |easy: &mut Easy, kind, why: fmt::Arguments<'_>| {
        Err(fail(easy, kind, crate::trace::reason(why)))
    };
    if matches!(call, Call::StartFrame(..)) && options.raw {
        let why = format_args!("cannot curl_ws_start_frame() with CURLWS_RAW_MODE enabled");
        return refuse(easy, ErrorKind::FailedInit, why);
    }
    if !easy.options().connect_only.reserves() {
        return match call {
            Call::Recv(_) => refuse(
                easy,
                ErrorKind::UnsupportedProtocol,
                format_args!("[WS] CONNECT_ONLY is required"),
            ),
            Call::Send(..) | Call::StartFrame(..) => refuse(
                easy,
                ErrorKind::SendError,
                format_args!("[WS] No associated connection"),
            ),
        };
    }
    let last = easy.last_conn;
    // A frame is started on the connection a receive or a send took up
    // again: it looks for none itself (`data->conn`).
    if matches!(call, Call::StartFrame(..)) && !last.is_some_and(|l| l.used) {
        let why = format_args!("[WS] No associated connection");
        return refuse(easy, ErrorKind::SendError, why);
    }
    let Some(conn) = last.and_then(|l| pool?.reserved_mut(l.id)) else {
        easy.last_conn = None;
        easy.report_mut().set_conn(None);
        return match call {
            Call::Recv(_) => refuse(
                easy,
                ErrorKind::BadFunctionArgument,
                format_args!("[WS] connection not found"),
            ),
            Call::Send(..) | Call::StartFrame(..) => refuse(
                easy,
                ErrorKind::UnsupportedProtocol,
                format_args!("Failed to get last socket used for connection #-1"),
            ),
        };
    };
    if let Some(l) = easy.last_conn.as_mut() {
        l.used = true;
    }
    let Some((ws, carrier)) = conn.ws_mut() else {
        return match call {
            Call::Recv(_) => refuse(
                easy,
                ErrorKind::BadFunctionArgument,
                format_args!("[WS] connection is not setup for websocket"),
            ),
            Call::Send(..) | Call::StartFrame(..) => refuse(
                easy,
                ErrorKind::SendError,
                format_args!("[WS] Not a websocket transfer"),
            ),
        };
    };
    let mut wire = RawWire {
        cx: RawCx { now, easy },
        carrier,
    };
    let raw = options.raw;
    match call {
        Call::Recv(buf) => {
            crate::proto::ws::api_recv(ws, &mut wire, buf, raw, options.auto_pong(), false)
                .map(Answer::Received)
        }
        Call::Send(bytes, len, flags) => {
            crate::proto::ws::api_send(ws, &mut wire, raw, bytes, len, flags, false)
                .map(Answer::Sent)
        }
        Call::StartFrame(flags, len) => {
            crate::proto::ws::api_start_frame(ws, &mut wire, raw, flags, len)
                .map(|()| Answer::Started)
        }
    }
}

impl<H: Host> Multi<H> {
    /// A call on the WebSocket transfer `id` only connected, once it is
    /// done. `None` if `id` is not in this multi.
    pub fn ws(
        &mut self,
        id: TransferId,
        call: crate::ws::Call<'_>,
    ) -> Option<Result<crate::ws::Answer, ErrorKind>> {
        let now = self.clock.now();
        let easy = &mut self.slots.get_mut(id)?.easy;
        Some(in_pool(Some(&mut self.caches.pool), easy, |pool, easy| {
            ws(pool, easy, now, call)
        }))
    }

    /// As `ws`, for `easy`, not added, whose transfers this multi ran.
    pub fn ws_for(
        &mut self,
        easy: &mut Easy,
        call: crate::ws::Call<'_>,
    ) -> Result<crate::ws::Answer, ErrorKind> {
        let now = self.clock.now();
        in_pool(Some(&mut self.caches.pool), easy, |pool, easy| {
            ws(pool, easy, now, call)
        })
    }
}

impl Easy {
    /// A call on the WebSocket the handle's last transfer only connected,
    /// once `perform` is done.
    pub fn ws(&mut self, call: crate::ws::Call<'_>) -> Result<crate::ws::Answer, ErrorKind> {
        match self.private.take() {
            Some(mut private) => {
                let done = private.multi.ws_for(self, call);
                self.private = Some(private);
                done
            }
            None => in_pool(None, self, |pool, easy| ws(pool, easy, no_clock(), call)),
        }
    }

    /// A call on the handle's WebSocket is refused before it reaches it,
    /// for `why`: its reason kept as the WebSocket's own would be.
    /// `kind`, given back.
    pub fn ws_refuse(&mut self, kind: ErrorKind, why: &[u8]) -> ErrorKind {
        fail(self, kind, crate::trace::reason_with(&[why]))
    }
}
