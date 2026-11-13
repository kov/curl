//! What a handle does itself with the connection its transfer only made
//! (`CURLOPT_CONNECT_ONLY`): bytes sent and received on it
//! (`curl_easy_send`, `curl_easy_recv`) and its socket told
//! (`CURLINFO_ACTIVESOCKET`). The connection stays reserved for the handle
//! in the pool it was made in (`Place::Reserved`), which the handle names
//! by its last connection. Also what a handle does with its pool's
//! connections between transfers: keep them alive (`curl_easy_upkeep`).
//!
//! No transfer runs for these calls. What they trace is the handle's, as
//! C's is, after the numbers its last transfer had, and is told to the
//! `notes` each call is given.

use std::fmt;

use super::{Host, Multi, TransferId};
use crate::components::Component;
use crate::conn::io::{Recv, Sent, SocketKey};
use crate::conn::layer::LayerCx;
use crate::conn::pool::Pool;
use crate::conn::{Conn, RecvFailed};
use crate::easy::Easy;
use crate::error::ErrorKind;
use crate::share::{Kind, Share, watched};
use crate::time::Instant;
use crate::trace::note_line;

/// What a call on the connection a transfer left traces, each piece as it
/// goes to the handle's debug function or standard error: the call has no
/// `TransferCx` to reach a debug handler with, and the handle is borrowed
/// meanwhile, so whoever made the call says them.
pub type Notes<'a> = &'a mut (dyn FnMut(crate::handler::DebugKind, &[u8]) + 'a);

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

/// The context of a raw send or receive: what it traces goes to `notes`;
/// a failure is kept in the handle's report and told to its error sink, as
/// C's `failf` keeps it.
struct RawCx<'a> {
    now: Instant,
    unix_time: i64,
    easy: &'a mut Easy,
    /// The multi's TLS sessions, for a handle in one (C's `data->multi`,
    /// which a perform's own multi leaves as it ends).
    sessions: Option<&'a mut crate::tls::SessionCache>,
    notes: Notes<'a>,
}

impl LayerCx for RawCx<'_> {
    fn now(&self) -> Instant {
        self.now
    }

    fn trace(&mut self) -> Option<&mut dyn crate::conn::layer::Trace> {
        Some(self)
    }

    fn failures(&mut self) -> Option<&mut dyn crate::conn::layer::Failures> {
        Some(self)
    }

    fn transfer(&mut self) -> Option<&mut dyn crate::conn::layer::ForTransfer> {
        Some(self)
    }

    /// The share's, if it keeps them (`cf_ssl_scache_get`), else its
    /// multi's; a handle with neither keeps none.
    fn tls_sessions(&mut self) -> Option<&mut dyn crate::conn::layer::TlsSessions> {
        let shared = self.easy.shared(Kind::SslSessions).is_some();
        (shared || self.sessions.is_some()).then_some(self as _)
    }

    fn early_data(&mut self) -> Option<&mut dyn crate::conn::layer::EarlyData> {
        None
    }

    fn quic_timer(&mut self) -> Option<&mut dyn crate::conn::layer::QuicTimer> {
        None
    }

    fn h3_event(
        &mut self,
        _stream: crate::http3::StreamId,
        _event: &crate::http3::StreamEvent<'_>,
    ) -> crate::http3::Heard {
        crate::http3::Heard::Fine
    }

    fn recv_room(&mut self) -> Option<&mut crate::conn::quic::RecvRoom> {
        None
    }

    fn recv_buf(&mut self) -> Option<&mut crate::conn::buf::XferBuf> {
        None
    }
}

impl crate::conn::layer::TlsSessions for RawCx<'_> {
    /// As a step's use (`StepCx`): what it says of a share's held until the
    /// share's lock is let go, as nothing is called out from inside it.
    fn with_cache(
        &mut self,
        f: &mut dyn FnMut(&mut crate::tls::SessionCache, &mut dyn crate::conn::layer::SessionSays),
    ) {
        use crate::conn::layer::LayerCalls as _;
        if let Some(share) = self.easy.shared(Kind::SslSessions).cloned() {
            let mut held = super::state::HeldSays {
                traces: crate::trace::handle_traces(self.easy, Component::Ssls),
                lines: Vec::new(),
                failure: None,
            };
            let watch = self.easy.share_watch.clone();
            watched(watch.as_deref(), &share, Kind::SslSessions, || {
                // Gone since it was chosen, it is no cache.
                if let Some(cache) = share.sessions().as_mut() {
                    f(cache, &mut held);
                }
            });
            for line in &held.lines {
                self.of_with(Component::Ssls, &[line]);
            }
            if let Some((kind, why)) = held.failure {
                self.fails_with(kind, &[&why]);
            }
            return;
        }
        if let Some(own) = self.sessions.take() {
            f(own, self);
            self.sessions = Some(own);
        }
    }
}

impl crate::conn::layer::Trace for RawCx<'_> {
    fn line(&mut self, component: Component, line: fmt::Arguments<'_>) {
        note_line(self.easy, Some(component), &mut *self.notes, |l| {
            l.push_fmt(line);
        });
    }

    fn line_with(&mut self, component: Component, parts: &[&[u8]]) {
        note_line(self.easy, Some(component), &mut *self.notes, |l| {
            for part in parts {
                l.push_clipped(part);
            }
        });
    }

    fn info_line(&mut self, line: fmt::Arguments<'_>) {
        note_line(self.easy, None, &mut *self.notes, |l| {
            l.push_fmt(line);
        });
    }

    fn info_line_with(&mut self, parts: &[&[u8]]) {
        note_line(self.easy, None, &mut *self.notes, |l| {
            for part in parts {
                l.push_clipped(part);
            }
        });
    }

    fn says_info(&self) -> bool {
        self.easy.options().output.verbose
    }

    fn traces(&self, component: Component) -> bool {
        crate::trace::handle_traces(self.easy, component)
    }
}

/// A connection made already asks little of its handle: a TLS session
/// traces its records and keeps its tickets.
impl crate::conn::layer::ForTransfer for RawCx<'_> {
    fn debug_bytes(&mut self, kind: crate::handler::DebugKind, bytes: &[u8]) {
        crate::trace::note_bytes(self.easy, kind, bytes, &mut *self.notes);
    }

    fn has_debug_handler(&self) -> bool {
        let options = self.easy.options();
        options.callbacks.rare.debug.is_some() && options.output.verbose
    }

    fn certinfo_report(&mut self) -> Option<&mut crate::report::TransferReport> {
        None
    }

    fn peer_verified(&mut self, _: Component, _: i64) {}

    fn has_tls_handler(&self) -> bool {
        false
    }

    fn hand_tls_context(&mut self, _: crate::tls::TlsNative) -> Result<(), ErrorKind> {
        Ok(())
    }

    fn stop_recv(&mut self) {}

    fn seconds_since_1970(&self) -> i64 {
        self.unix_time
    }
}

impl crate::conn::layer::Failures for RawCx<'_> {
    fn keep(&mut self, kind: ErrorKind, why: fmt::Arguments<'_>) -> ErrorKind {
        fail(self.easy, kind, crate::trace::reason(why), &mut *self.notes)
    }

    fn keep_with(&mut self, kind: ErrorKind, parts: &[&[u8]]) -> ErrorKind {
        let why = crate::trace::reason_with(parts);
        fail(self.easy, kind, why, &mut *self.notes)
    }

    fn keep_errno(&mut self, e: &std::io::Error) {
        self.easy.report_mut().socket_failed(e);
    }
}

/// Keep `why` as the reason the handle failed, if it is the first, tell
/// the application's error sink and trace it (`failf` outside a transfer).
fn fail(
    easy: &mut Easy,
    kind: ErrorKind,
    reason: crate::trace::Reason,
    notes: Notes<'_>,
) -> ErrorKind {
    let detail = reason.bytes();
    let first = easy.report().unsaid();
    easy.report_mut().record_failure(detail);
    if first && let Some(sink) = easy.options().callbacks.failure.clone() {
        sink.write(detail);
    }
    crate::trace::note_failure(easy, detail, notes);
    kind
}

/// The clock of a call on a connection: the multi's that made it, or a
/// handle with no multi's own, whose layers keep no time but their own.
#[derive(Clone, Copy)]
struct When {
    now: Instant,
    unix_time: i64,
}

impl When {
    fn of(clock: &crate::time::SharedClock) -> When {
        When {
            now: clock.now(),
            unix_time: clock.unix_time(),
        }
    }

    fn on_no_clock() -> When {
        let clock = crate::time::SystemClock::new();
        When {
            now: clock.now(),
            unix_time: clock.unix_time(),
        }
    }
}

/// Run `f` on the pool `easy`'s connections are in: its share's, if that
/// keeps connections, under its lock; else `own`, the multi's, if there
/// is one.
fn in_pool<R>(
    own: Option<&mut Pool>,
    easy: &mut Easy,
    f: impl FnOnce(Option<&mut Pool>, &mut Easy) -> R,
) -> R {
    let share = easy.shared(Kind::Connections).cloned();
    in_pool_of(share, own, easy, f)
}

/// As `in_pool`, the pool `share`'s, if any, as the caller found it.
fn in_pool_of<R>(
    share: Option<Share>,
    own: Option<&mut Pool>,
    easy: &mut Easy,
    f: impl FnOnce(Option<&mut Pool>, &mut Easy) -> R,
) -> R {
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

/// What a call on a connection reaches beside its handle: the pool it may
/// be in, the sessions of a handle in a multi, and the clock.
pub(crate) struct Around<'a> {
    pool: Option<&'a mut Pool>,
    sessions: Option<&'a mut crate::tls::SessionCache>,
    when: When,
}

/// Run `io` on the connection `easy` reserved, if its pool still has it:
/// its share's if that keeps connections, else `own`. The pool is locked
/// and its lock told of only to find the connection
/// (`Curl_cpool_get_last_conn`), and locked again, untold, to put it back:
/// `io` runs out of the lock, as C's reads and writes do.
fn on_reserved<R>(
    mut own: Option<&mut Pool>,
    easy: &mut Easy,
    io: impl FnOnce(&mut Easy, Option<&mut Conn>) -> R,
) -> R {
    // Put back where it was found, whatever the share keeps by then.
    let share = easy.shared(Kind::Connections).cloned();
    let lent = in_pool_of(share.clone(), own.as_deref_mut(), easy, |pool, easy| {
        easy.last_conn.and_then(|l| pool?.lend_reserved(l.id))
    });
    let Some(mut lent) = lent else {
        return io(easy, None);
    };
    let done = io(easy, Some(lent.conn_mut()));
    match share {
        Some(share) => share.pool().return_reserved(lent),
        None => own
            .expect("lent by the pool it was found in")
            .return_reserved(lent),
    }
    done
}

/// A raw send or receive on the connection `easy` reserved, in `pool`
/// (`curl_easy_send`, `curl_easy_recv`): refused for a handle that does
/// not only connect.
fn raw(
    around: Around<'_>,
    easy: &mut Easy,
    way: Way<'_>,
    notes: Notes<'_>,
) -> Result<RawIo, ErrorKind> {
    let Around {
        pool,
        sessions,
        when,
    } = around;
    if !easy.options().connect_only.reserves() {
        let why = format_args!("CONNECT_ONLY is required");
        return Err(fail(
            easy,
            ErrorKind::UnsupportedProtocol,
            crate::trace::reason(why),
            notes,
        ));
    }
    on_reserved(pool, easy, |easy, conn| {
        raw_on_conn(conn, easy, sessions, when, way, notes)
    })
}

/// `raw`, on the connection found; refused if it is gone, which the handle
/// then forgets (`easy_connection`, `Curl_cpool_get_last_conn`).
fn raw_on_conn(
    conn: Option<&mut Conn>,
    easy: &mut Easy,
    sessions: Option<&mut crate::tls::SessionCache>,
    when: When,
    way: Way<'_>,
    notes: Notes<'_>,
) -> Result<RawIo, ErrorKind> {
    let Some(conn) = conn else {
        // Forgotten as it is looked for, so C names it as none.
        easy.last_conn = None;
        easy.report_mut().set_conn(None);
        let why = format_args!("Failed to get last socket used for connection #-1");
        return Err(fail(
            easy,
            ErrorKind::UnsupportedProtocol,
            crate::trace::reason(why),
            notes,
        ));
    };
    if let Some(l) = easy.last_conn.as_mut() {
        l.used = true;
    }
    let mut cx = RawCx {
        now: when.now,
        unix_time: when.unix_time,
        easy,
        sessions,
        notes,
    };
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
    pub fn recv_raw(
        &mut self,
        id: TransferId,
        buf: &mut [u8],
        notes: Notes<'_>,
    ) -> Option<Result<RawIo, ErrorKind>> {
        self.raw_on(id, Way::Recv(buf), notes)
    }

    /// Send from `bytes` on the connection transfer `id` only made, once
    /// it is done (`curl_easy_send`). `None` if `id` is not in this multi.
    pub fn send_raw(
        &mut self,
        id: TransferId,
        bytes: &[u8],
        notes: Notes<'_>,
    ) -> Option<Result<RawIo, ErrorKind>> {
        self.raw_on(id, Way::Send(bytes), notes)
    }

    fn raw_on(
        &mut self,
        id: TransferId,
        way: Way<'_>,
        notes: Notes<'_>,
    ) -> Option<Result<RawIo, ErrorKind>> {
        let around = Around {
            pool: Some(&mut self.caches.pool),
            sessions: Some(&mut self.caches.sessions),
            when: When::of(&self.clock),
        };
        let easy = self.slots.app_easy_mut(id)?;
        Some(raw(around, easy, way, notes))
    }

    /// The socket of the connection transfer `id` had last, if it is
    /// still open: the one it holds, or one its pool keeps
    /// (`CURLINFO_ACTIVESOCKET`, `Curl_getconnectinfo`). `None` if `id` is
    /// not in this multi.
    pub fn active_socket(&mut self, id: TransferId) -> Option<Option<SocketKey>> {
        let (slot, edits) = self.slots.app_mut_counted(id)?;
        if let Some(lease) = slot.run.as_ref().and_then(|r| r.state.lease()) {
            let slot = self.caches.pool.slot_of(lease);
            return Some(slot.and_then(|s| s.sockets().next()).map(|s| s.key()));
        }
        Some(in_pool(
            Some(&mut self.caches.pool),
            slot.easy.easy_mut(edits),
            pool_socket,
        ))
    }

    /// As `recv_raw`, for `easy`, not added, whose transfers this multi
    /// ran.
    pub fn recv_raw_for(
        &mut self,
        easy: &mut Easy,
        buf: &mut [u8],
        notes: Notes<'_>,
    ) -> Result<RawIo, ErrorKind> {
        raw(self.around_for(), easy, Way::Recv(buf), notes)
    }

    /// As `send_raw`, for `easy`, not added, whose transfers this multi
    /// ran.
    pub fn send_raw_for(
        &mut self,
        easy: &mut Easy,
        bytes: &[u8],
        notes: Notes<'_>,
    ) -> Result<RawIo, ErrorKind> {
        raw(self.around_for(), easy, Way::Send(bytes), notes)
    }

    /// What a call by a handle not added reaches of this multi, which ran
    /// its transfers: its pool, not its sessions, C's `data->multi` being
    /// none once a perform is done.
    pub(crate) fn around_for(&mut self) -> Around<'_> {
        Around {
            pool: Some(&mut self.caches.pool),
            sessions: None,
            when: When::of(&self.clock),
        }
    }

    /// The connections this multi keeps.
    pub(crate) fn kept_pool(&self) -> &Pool {
        &self.caches.pool
    }

    pub(crate) fn kept_pool_mut(&mut self) -> &mut Pool {
        &mut self.caches.pool
    }

    /// As `tls_native`, for `easy`, not added, whose transfers this multi
    /// ran.
    pub fn tls_native_for(&self, easy: &Easy) -> Option<crate::tls::TlsNative> {
        reserved_tls_native(Some(&self.caches.pool), easy)
    }

    /// As `active_socket`, for `easy`, not added, whose transfers this
    /// multi ran.
    pub fn active_socket_for(&mut self, easy: &mut Easy) -> Option<SocketKey> {
        in_pool(Some(&mut self.caches.pool), easy, pool_socket)
    }
}

/// The TLS library's objects of the connection `easy` reserved, once a
/// call took it up (C's `data->conn`, which that sets): none before, as
/// the transfer that made it has let it go.
pub(super) fn reserved_tls_native(
    own: Option<&Pool>,
    easy: &Easy,
) -> Option<crate::tls::TlsNative> {
    let last = easy.last_conn.filter(|l| l.used)?;
    match easy.shared(Kind::Connections) {
        Some(share) => share.pool().reserved_tls_native(last.id),
        None => own?.reserved_tls_native(last.id),
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
    crate::time::SystemClock::new().now()
}

impl Around<'static> {
    /// What a call by a handle that no multi ran reaches: nothing.
    fn alone() -> Around<'static> {
        Around {
            pool: None,
            sessions: None,
            when: When::on_no_clock(),
        }
    }
}

impl Easy {
    /// The TLS library's objects of the connection the handle's last
    /// transfer only made, once a call took it up
    /// (`CURLINFO_TLS_SSL_PTR`).
    pub fn tls_native(&self) -> Option<crate::tls::TlsNative> {
        match &self.private {
            Some(private) => reserved_tls_native(Some(private.0.pool()), self),
            None => reserved_tls_native(None, self),
        }
    }

    /// Keep alive the connections of the handle's pool that have gone its
    /// upkeep interval without (`curl_easy_upkeep`): an HTTP/2 connection
    /// is sent a PING, others nothing. The pool is its share's, if that
    /// keeps connections, else the one `perform` keeps; a handle with
    /// neither has none to keep.
    pub fn upkeep(&mut self) -> Result<(), curl_alloc::OutOfMemory> {
        match self.private.take() {
            Some(mut private) => {
                let kept = private.0.upkeep_for(self);
                self.private = Some(private);
                kept
            }
            None => {
                if let Some(share) = self.shared(Kind::Connections) {
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
    pub fn recv_raw(&mut self, buf: &mut [u8], notes: Notes<'_>) -> Result<RawIo, ErrorKind> {
        match self.private.take() {
            Some(mut private) => {
                let got = raw(private.0.around(), self, Way::Recv(buf), notes);
                self.private = Some(private);
                got
            }
            None => raw(Around::alone(), self, Way::Recv(buf), notes),
        }
    }

    /// Send from `bytes` on the connection the handle's last transfer
    /// only made (`curl_easy_send`), once `perform` is done.
    pub fn send_raw(&mut self, bytes: &[u8], notes: Notes<'_>) -> Result<RawIo, ErrorKind> {
        match self.private.take() {
            Some(mut private) => {
                let sent = raw(private.0.around(), self, Way::Send(bytes), notes);
                self.private = Some(private);
                sent
            }
            None => raw(Around::alone(), self, Way::Send(bytes), notes),
        }
    }

    /// The socket of the connection the handle's last transfer had, if
    /// its pool still keeps it open (`CURLINFO_ACTIVESOCKET`).
    pub fn active_socket(&mut self) -> Option<SocketKey> {
        match self.private.take() {
            Some(mut private) => {
                let socket = in_pool(Some(private.0.pool_mut()), self, pool_socket);
                self.private = Some(private);
                socket
            }
            None => in_pool(None, self, pool_socket),
        }
    }
}

/// The connection a handle's transfer only made, as its WebSocket's
/// frames go out on it and come in from it (`Curl_senddata`,
/// `Curl_easy_recv`).
struct RawWire<'a> {
    cx: RawCx<'a>,
    carrier: crate::conn::mux::Carrier<'a>,
}

impl crate::proto::ws::Said for RawWire<'_> {
    fn ws(&mut self, args: fmt::Arguments<'_>) {
        crate::conn::layer::Trace::line(&mut self.cx, Component::Ws, args);
    }

    fn info(&mut self, args: fmt::Arguments<'_>) {
        crate::conn::layer::Trace::info_line(&mut self.cx, args);
    }

    fn fail(&mut self, kind: ErrorKind, why: fmt::Arguments<'_>) -> ErrorKind {
        let why = crate::trace::reason(why);
        fail(self.cx.easy, kind, why, &mut *self.cx.notes)
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

/// A [`Call`](crate::ws::Call) with its typed arguments read as a host's.
enum WsCall<'a> {
    Recv(&'a mut [u8]),
    Send(&'a [u8], crate::ws::Asked<'a>),
    StartFrame(crate::ws::Asked<'a>),
}

/// A call on the WebSocket of the connection `easy` reserved, in `pool`
/// (`curl_ws_recv`, `curl_ws_send`, `curl_ws_start_frame` once the
/// transfer is done): refused for a handle that does not only connect.
fn ws(
    around: Around<'_>,
    easy: &mut Easy,
    call: crate::ws::Call<'_>,
    notes: Notes<'_>,
) -> Result<crate::ws::Answer, ErrorKind> {
    use crate::proto::ws::{asked_of, send_enters, start_asked_of, start_enters};
    use crate::ws::{AskedFrame, Call};
    let Around {
        pool,
        sessions,
        when,
    } = around;
    let options = easy.options().ws;
    let refuse = |easy: &mut Easy, notes: Notes<'_>, kind, why: fmt::Arguments<'_>| {
        Err(fail(easy, kind, crate::trace::reason(why), notes))
    };
    let call = match call {
        Call::Recv(buf) => WsCall::Recv(buf),
        Call::Send(bytes, len, flags) => WsCall::Send(bytes, asked_of(len, flags)),
        Call::SendAsked(bytes, asked) => WsCall::Send(bytes, asked),
        Call::StartFrame(flags, len) => WsCall::StartFrame(start_asked_of(flags, len)),
        Call::StartAsked(asked) => WsCall::StartFrame(asked),
    };
    match &call {
        WsCall::Recv(_) => {}
        WsCall::Send(bytes, asked) => {
            send_enters(bytes.len(), asked, options.raw, |line| {
                note_line(easy, Some(Component::Ws), &mut *notes, |l| {
                    l.push_fmt(line);
                });
            });
            if let AskedFrame::NoBytes { why, .. } = asked.frame {
                let reason = format_args!("{}", why.why);
                return refuse(easy, notes, why.kind, reason);
            }
        }
        WsCall::StartFrame(asked) => {
            if options.raw {
                let why = format_args!("cannot curl_ws_start_frame() with CURLWS_RAW_MODE enabled");
                return refuse(easy, notes, ErrorKind::FailedInit, why);
            }
            start_enters(asked, |line| {
                note_line(easy, Some(Component::Ws), &mut *notes, |l| {
                    l.push_fmt(line);
                });
            });
        }
    }
    if !easy.options().connect_only.reserves() {
        return match call {
            WsCall::Recv(_) => refuse(
                easy,
                notes,
                ErrorKind::UnsupportedProtocol,
                format_args!("[WS] CONNECT_ONLY is required"),
            ),
            WsCall::Send(..) | WsCall::StartFrame(_) => refuse(
                easy,
                notes,
                ErrorKind::SendError,
                format_args!("[WS] No associated connection"),
            ),
        };
    }
    let last = easy.last_conn;
    // A frame is started on the connection a receive or a send took up
    // again: it looks for none itself (`data->conn`).
    if matches!(call, WsCall::StartFrame(_)) && !last.is_some_and(|l| l.used) {
        let why = format_args!("[WS] No associated connection");
        return refuse(easy, notes, ErrorKind::SendError, why);
    }
    on_reserved(pool, easy, |easy, conn| {
        ws_on_conn(conn, easy, sessions, when, call, notes)
    })
}

/// `ws`, on the connection found; refused if it is gone, which the handle
/// then forgets, or is not a WebSocket's.
fn ws_on_conn(
    conn: Option<&mut Conn>,
    easy: &mut Easy,
    sessions: Option<&mut crate::tls::SessionCache>,
    when: When,
    call: WsCall<'_>,
    notes: Notes<'_>,
) -> Result<crate::ws::Answer, ErrorKind> {
    use crate::ws::Answer;
    let options = easy.options().ws;
    let refuse = |easy: &mut Easy, notes: Notes<'_>, kind, why: fmt::Arguments<'_>| {
        Err(fail(easy, kind, crate::trace::reason(why), notes))
    };
    let Some(conn) = conn else {
        easy.last_conn = None;
        easy.report_mut().set_conn(None);
        return match call {
            WsCall::Recv(_) => refuse(
                easy,
                notes,
                ErrorKind::BadFunctionArgument,
                format_args!("[WS] connection not found"),
            ),
            WsCall::Send(..) | WsCall::StartFrame(_) => refuse(
                easy,
                notes,
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
            WsCall::Recv(_) => refuse(
                easy,
                notes,
                ErrorKind::BadFunctionArgument,
                format_args!("[WS] connection is not setup for websocket"),
            ),
            WsCall::Send(..) | WsCall::StartFrame(_) => refuse(
                easy,
                notes,
                ErrorKind::SendError,
                format_args!("[WS] Not a websocket transfer"),
            ),
        };
    };
    let mut wire = RawWire {
        cx: RawCx {
            now: when.now,
            unix_time: when.unix_time,
            easy,
            sessions,
            notes,
        },
        carrier,
    };
    let raw = options.raw;
    match call {
        WsCall::Recv(buf) => {
            crate::proto::ws::api_recv(ws, &mut wire, buf, raw, options.auto_pong(), false)
                .map(Answer::Received)
        }
        WsCall::Send(bytes, asked) => {
            crate::proto::ws::api_send(ws, &mut wire, raw, bytes, &asked, false).map(Answer::Sent)
        }
        WsCall::StartFrame(asked) => {
            crate::proto::ws::api_start_frame(ws, &mut wire, &asked).map(|()| Answer::Started)
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
        notes: Notes<'_>,
    ) -> Option<Result<crate::ws::Answer, ErrorKind>> {
        let around = Around {
            pool: Some(&mut self.caches.pool),
            sessions: Some(&mut self.caches.sessions),
            when: When::of(&self.clock),
        };
        let easy = self.slots.app_easy_mut(id)?;
        Some(ws(around, easy, call, notes))
    }

    /// As `ws`, for `easy`, not added, whose transfers this multi ran.
    pub fn ws_for(
        &mut self,
        easy: &mut Easy,
        call: crate::ws::Call<'_>,
        notes: Notes<'_>,
    ) -> Result<crate::ws::Answer, ErrorKind> {
        ws(self.around_for(), easy, call, notes)
    }
}

impl Easy {
    /// A call on the WebSocket the handle's last transfer only connected,
    /// once `perform` is done.
    pub fn ws(
        &mut self,
        call: crate::ws::Call<'_>,
        notes: Notes<'_>,
    ) -> Result<crate::ws::Answer, ErrorKind> {
        match self.private.take() {
            Some(mut private) => {
                let done = ws(private.0.around(), self, call, notes);
                self.private = Some(private);
                done
            }
            None => ws(Around::alone(), self, call, notes),
        }
    }
}
