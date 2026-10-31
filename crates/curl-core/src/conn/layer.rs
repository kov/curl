//! The layers a connection's bytes pass through between the socket and
//! the protocol (C's connection filters, `cfilters.h`), as a pull chain: a
//! read asks the top layer for at most the caller's length, and each layer
//! reads from the one below it as it needs, down to the socket. A layer
//! that works on the bytes (TLS) is boxed on the stream; those that only
//! pass them once connected (SOCKS, an HTTP proxy's tunnel) are kinds kept
//! inline, so a stream over TCP, a SOCKS proxy or a tunnel allocates
//! nothing for its layers.

use std::cell::Cell;
use std::fmt;
use std::io;
use std::time::Duration;

use curl_alloc::{OutOfMemory, TryVec as _, try_box};

use super::io::{Events, Recv, Sent, Socket, SocketPoll, poll_together};
pub(crate) use super::part::{Lower, Part};
use crate::components::Component;
use crate::error::{AGAIN_NUMBER, ErrorKind};
use crate::time::Instant;

/// What a layer's handshake, or its shutdown, came to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Handshake {
    Done,
    /// It waits for the socket.
    Waiting,
}

/// Whether a connection seems usable, as its layers and its socket say
/// (`Curl_conn_is_alive`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Alive {
    Dead,
    /// Usable; with input waiting, which an idle HTTP/1 connection must
    /// not have.
    Alive {
        input_pending: bool,
    },
}

/// A question asked of a connection's layers, from the top (C's
/// `cf->cft->query`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum LayerQuery {
    /// The origin's TLS library's own objects (`CF_QUERY_SSL_INFO`,
    /// `CF_QUERY_SSL_CTX_INFO`).
    TlsNative,
    /// The protocol the origin's TLS session agreed by ALPN
    /// (`CF_QUERY_ALPN_NEGOTIATED`).
    Alpn,
    /// What the origin's TLS session waits for on the socket (its
    /// `io_need`).
    TlsWaits,
    /// What an HTTPS proxy's TLS session waits for, likewise.
    ProxyTlsWaits,
    /// The origin's TLS handshake is put off for early data
    /// (`ssl_connection_deferred`).
    TlsDeferred,
    /// What a layer's send or receive failed with, where it names the
    /// transfer's error: a handshake put off failing as it goes on.
    Failure,
    /// The filter of the tunnel through a proxy, when a layer is it:
    /// `H2-PROXY`'s, a stream of an HTTP/2 session.
    Tunnel,
}

/// What a layer answers a `LayerQuery`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum LayerAnswer {
    TlsNative(crate::tls::TlsNative),
    /// What the peer chose, if it chose, and the TLS filter that says
    /// so: the origin's or an HTTPS proxy's.
    Alpn(Option<crate::tls::Chosen>, Component),
    TlsWaits(crate::tls::TlsWait),
    TlsDeferred,
    Failure(ErrorKind),
    Tunnel(Component),
}

/// What a layer reaches while it works: the time, and each capability of
/// what the work is for, which the context lends or not. An argument,
/// never stored. Every context says what it lends, with no default: a
/// context over another's lends that one's, or says why not; a pool's
/// section, which works for no transfer, lends nothing (`Silent`). What
/// a layer calls on it (`LayerCalls`) asks the capability it needs, and
/// is nothing, or the answer of work for no transfer, where none is lent.
pub(crate) trait LayerCx {
    fn now(&self) -> Instant;

    /// The trace the work's lines go to: the transfer's, or the internal
    /// handle's; none where nothing traces the work.
    fn trace(&mut self) -> Option<&mut dyn Trace>;

    /// What keeps the work's failures: the transfer's error and its
    /// socket's error number, or a handle's; none where nothing does.
    fn failures(&mut self) -> Option<&mut dyn Failures>;

    /// The transfer the work is for, in what the TLS filter asks of it:
    /// its debug handler, its report, its TLS context handler, its pause
    /// and the time of day. None for work done for no transfer.
    fn transfer(&mut self) -> Option<&mut dyn ForTransfer>;

    /// The cache of TLS sessions the work keeps its connection's in: its
    /// share's or its multi's (`cf_ssl_scache_get`). None for work done
    /// for no transfer.
    fn tls_sessions(&mut self) -> Option<&mut dyn TlsSessions>;

    /// What takes the word that a handshake put off for early data is
    /// done (`Curl_pgrsEarlyData`): the stepping transfer's report.
    fn early_data(&mut self) -> Option<&mut dyn EarlyData>;

    /// The timer a QUIC connection's library is called again by
    /// (`Curl_expire_set(EXPIRE_QUIC)`): the transfer's.
    fn quic_timer(&mut self) -> Option<&mut dyn QuicTimer>;

    /// Who hears what a QUIC connection's HTTP/3 library tells of its
    /// streams, as it reads or writes for the work: a stream's transfer,
    /// or a tunnel's. Work with no streams has none, and hears it as
    /// nothing.
    fn h3_streams(&mut self) -> Option<&mut dyn H3Streams>;

    /// The multi's room a QUIC connection on a socket receives in, which
    /// the call lends (`Curl_multi_xfer_sockbuf_borrow`); none where the
    /// work has no multi's room to lend, and the receive makes one for
    /// the call, as C's does with no multi.
    fn recv_room(&mut self) -> Option<&mut crate::conn::quic::RecvRoom>;
}

/// A trace's lines (`CURL_TRC_CF`, `infof`).
pub(crate) trait Trace {
    /// A line of `component`'s, if it is traced.
    fn line(&mut self, component: Component, line: fmt::Arguments<'_>);

    /// `line` made of `parts`, which need not be text: bytes of the
    /// peer's or the application's, traced as they are, as C's `%s`
    /// writes them.
    fn line_with(&mut self, component: Component, parts: &[&[u8]]);

    /// A line of the verbose output (`infof`).
    fn info_line(&mut self, line: fmt::Arguments<'_>);

    /// `info_line` made of `parts`, which need not be text.
    fn info_line_with(&mut self, parts: &[&[u8]]);

    /// Its info lines are said (`Curl_trc_is_verbose`).
    fn says_info(&self) -> bool;
}

/// What keeps a failure: the reason, kept if it is the first and said
/// (`failf`), and the error number of a call on the socket that failed.
pub(crate) trait Failures {
    /// Fail with `kind` for the reason `why`; `kind` back.
    fn keep(&mut self, kind: ErrorKind, why: fmt::Arguments<'_>) -> ErrorKind;

    /// `keep` with a reason made of `parts`, which need not be text:
    /// bytes of the peer's, the application's or the system's.
    fn keep_with(&mut self, kind: ErrorKind, parts: &[&[u8]]) -> ErrorKind;

    /// A connect, send or receive on the socket failed with `e`: its
    /// number is kept (`state.os_errno`).
    fn keep_errno(&mut self, e: &io::Error);
}

/// What the TLS filter asks of the transfer it works for.
pub(crate) trait ForTransfer {
    /// Bytes for the debug handler (`Curl_debug`), if it is verbose.
    fn debug_bytes(&mut self, kind: crate::handler::DebugKind, bytes: &[u8]);

    /// It traces to a debug handler (C's `data->set.fdebug` and
    /// `verbose`).
    fn has_debug_handler(&self) -> bool;

    /// Its report, if it asked for its peer's chain (`CURLOPT_CERTINFO`).
    fn certinfo_report(&mut self) -> Option<&mut crate::report::TransferReport>;

    /// What the TLS library made of the certificate of the peer the TLS
    /// filter `filter` talks to, the origin (`SSL`) or an HTTPS proxy
    /// (`SSL-PROXY`), for its report (`set.ssl.certverifyresult`,
    /// `set.proxy_ssl.certverifyresult`).
    fn peer_verified(&mut self, filter: Component, result: i64);

    /// It has a TLS context handler (`CURLOPT_SSL_CTX_FUNCTION`).
    fn has_tls_handler(&self) -> bool;

    /// Hand the context in `native` to its TLS context handler; its
    /// error, if it gives one.
    fn hand_tls_context(&mut self, native: crate::tls::TlsNative) -> Result<(), ErrorKind>;

    /// It stops receiving until the application unpauses it
    /// (`Curl_xfer_pause_recv`).
    fn stop_recv(&mut self);

    /// The time of day, in seconds since 1970 (`time(NULL)`).
    fn seconds_since_1970(&self) -> i64;
}

/// A cache of TLS sessions, and what a use of it says.
pub(crate) trait TlsSessions {
    /// Run `f` on the cache, with what says its lines and failure: the
    /// share's under its lock, the application told around it
    /// (`Curl_ssl_scache_lock`), or the multi's.
    fn with_cache(
        &mut self,
        f: &mut dyn FnMut(&mut crate::tls::SessionCache, &mut dyn SessionSays),
    );
}

/// What a use of a cache of TLS sessions says: the cache's lines and the
/// failure to keep a session.
pub(crate) trait SessionSays {
    fn say_line(&mut self, component: Component, line: fmt::Arguments<'_>);

    fn say_failure(&mut self, kind: ErrorKind, why: fmt::Arguments<'_>) -> ErrorKind;
}

/// A context's own lines and failure say what a use of a cache says.
impl<T: LayerCx + ?Sized> SessionSays for T {
    fn say_line(&mut self, component: Component, line: fmt::Arguments<'_>) {
        self.of(component, line);
    }

    fn say_failure(&mut self, kind: ErrorKind, why: fmt::Arguments<'_>) -> ErrorKind {
        self.fails(kind, why)
    }
}

/// What takes the word that a handshake put off for early data is done.
pub(crate) trait EarlyData {
    /// `sent` bytes went early, negative if the peer refused them: the
    /// transfer keeps the count, whichever hop's handshake it was
    /// (`Curl_pgrsEarlyData`).
    fn early_sent(&mut self, sent: i64);

    /// The origin's handshake, put off for early data, is done: the
    /// transfer times its TLS as done now (`TIMER_APPCONNECT`).
    fn connected_late(&mut self);
}

/// The timer a QUIC connection's library is called again by.
pub(crate) trait QuicTimer {
    /// Call it again after `wait` from now, in whole milliseconds.
    fn due_in(&mut self, wait: Duration);
}

/// Who hears what a QUIC connection's HTTP/3 library tells of a stream.
pub(crate) trait H3Streams {
    /// The library told `event` of `stream` (C's callbacks reach the
    /// stream's transfer).
    fn heard(
        &mut self,
        stream: crate::http3::StreamId,
        event: crate::http3::StreamEvent<'_>,
    ) -> crate::http3::Heard;
}

/// What a layer calls on its context, each through the capability it
/// needs: nothing, or the answer of work done for no transfer, where the
/// context lends none.
pub(crate) trait LayerCalls: LayerCx {
    /// Trace a line of `component`'s, if it is.
    fn of(&mut self, component: Component, line: fmt::Arguments<'_>) {
        if let Some(trace) = self.trace() {
            trace.line(component, line);
        }
    }

    /// `of` with a line made of `parts`, which need not be text.
    fn of_with(&mut self, component: Component, parts: &[&[u8]]) {
        if let Some(trace) = self.trace() {
            trace.line_with(component, parts);
        }
    }

    /// A line of the transfer's verbose output (`infof`).
    fn info(&mut self, line: fmt::Arguments<'_>) {
        if let Some(trace) = self.trace() {
            trace.info_line(line);
        }
    }

    /// `info` with a line made of `parts`, which need not be text.
    fn info_with(&mut self, parts: &[&[u8]]) {
        if let Some(trace) = self.trace() {
            trace.info_line_with(parts);
        }
    }

    /// The transfer is verbose (`Curl_trc_is_verbose`): its `info` lines
    /// are said.
    fn verbose(&mut self) -> bool {
        self.trace().is_some_and(|trace| trace.says_info())
    }

    /// A call on the socket failed with `e`: the transfer keeps its
    /// number (`state.os_errno`).
    fn socket_failed(&mut self, e: &io::Error) {
        if let Some(failures) = self.failures() {
            failures.keep_errno(e);
        }
    }

    /// The transfer fails with `kind`, for the reason `why` (`failf`):
    /// kept if it is the first given, and traced.
    fn fails(&mut self, kind: ErrorKind, why: fmt::Arguments<'_>) -> ErrorKind {
        match self.failures() {
            Some(failures) => failures.keep(kind, why),
            None => kind,
        }
    }

    /// `fails` with a reason made of `parts`, which need not be text.
    fn fails_with(&mut self, kind: ErrorKind, parts: &[&[u8]]) -> ErrorKind {
        match self.failures() {
            Some(failures) => failures.keep_with(kind, parts),
            None => kind,
        }
    }

    /// Bytes for the transfer's debug handler (`Curl_debug`), if it is
    /// verbose.
    fn bytes(&mut self, kind: crate::handler::DebugKind, bytes: &[u8]) {
        if let Some(transfer) = self.transfer() {
            transfer.debug_bytes(kind, bytes);
        }
    }

    /// The transfer traces to a debug handler.
    fn debugs(&mut self) -> bool {
        self.transfer().is_some_and(|t| t.has_debug_handler())
    }

    /// The report of the transfer, if it asked for its peer's chain.
    fn certinfo_report(&mut self) -> Option<&mut crate::report::TransferReport> {
        self.transfer()?.certinfo_report()
    }

    /// What the TLS library made of the certificate of the peer the TLS
    /// filter `filter` talks to, for the transfer's report.
    fn tls_verified(&mut self, filter: Component, result: i64) {
        if let Some(transfer) = self.transfer() {
            transfer.peer_verified(filter, result);
        }
    }

    /// The transfer has a TLS context handler.
    fn configures_tls(&mut self) -> bool {
        self.transfer().is_some_and(|t| t.has_tls_handler())
    }

    /// Hand the context in `native` to the transfer's TLS context
    /// handler; its error, if it gives one.
    fn configure_tls(&mut self, native: crate::tls::TlsNative) -> Result<(), ErrorKind> {
        match self.transfer() {
            Some(transfer) => transfer.hand_tls_context(native),
            None => Ok(()),
        }
    }

    /// The transfer stops receiving until the application unpauses it.
    fn pause_recv(&mut self) {
        if let Some(transfer) = self.transfer() {
            transfer.stop_recv();
        }
    }

    /// The time of day, in seconds since 1970; none, 0, for work done
    /// for no transfer.
    fn unix_time(&mut self) -> i64 {
        self.transfer().map_or(0, |t| t.seconds_since_1970())
    }

    /// The work has a cache of TLS sessions.
    fn has_tls_sessions(&mut self) -> bool {
        self.tls_sessions().is_some()
    }

    /// Run `f` on the cache of TLS sessions, if there is one.
    fn with_tls_sessions(
        &mut self,
        f: &mut dyn FnMut(&mut crate::tls::SessionCache, &mut dyn SessionSays),
    ) {
        if let Some(sessions) = self.tls_sessions() {
            sessions.with_cache(f);
        }
    }

    /// The origin's TLS handshake, put off for early data, is done
    /// (`ssl_cf_connect_deferred`): `sent` bytes went early, negative if
    /// the peer refused them.
    fn early_done(&mut self, sent: i64) {
        if let Some(early) = self.early_data() {
            early.early_sent(sent);
            early.connected_late();
        }
    }

    /// The same of an HTTP/3 proxy's handshake: the count is kept, the
    /// transfer's TLS not timed by it (`CF_TYPE_PROXY`).
    fn proxy_early_done(&mut self, sent: i64) {
        if let Some(early) = self.early_data() {
            early.early_sent(sent);
        }
    }

    /// A QUIC connection's library wants to be called again after `wait`
    /// from now (`Curl_expire_set(EXPIRE_QUIC)`).
    fn quic_due(&mut self, wait: Duration) {
        if let Some(timer) = self.quic_timer() {
            timer.due_in(wait);
        }
    }

    /// What a QUIC connection's HTTP/3 library told of one of its
    /// streams, handed to who hears it; work with no streams hears it as
    /// nothing.
    fn h3_event(
        &mut self,
        stream: crate::http3::StreamId,
        event: crate::http3::StreamEvent<'_>,
    ) -> crate::http3::Heard {
        match self.h3_streams() {
            Some(streams) => streams.heard(stream, event),
            None => crate::http3::Heard::Fine,
        }
    }
}

impl<T: LayerCx + ?Sized> LayerCalls for T {}

/// The context of work done for no transfer: it traces nothing, as C's
/// internal handle is not traced, and lends nothing.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Silent(pub(crate) Instant);

impl LayerCx for Silent {
    fn now(&self) -> Instant {
        self.0
    }

    fn trace(&mut self) -> Option<&mut dyn Trace> {
        None
    }

    fn failures(&mut self) -> Option<&mut dyn Failures> {
        None
    }

    fn transfer(&mut self) -> Option<&mut dyn ForTransfer> {
        None
    }

    fn tls_sessions(&mut self) -> Option<&mut dyn TlsSessions> {
        None
    }

    fn early_data(&mut self) -> Option<&mut dyn EarlyData> {
        None
    }

    fn quic_timer(&mut self) -> Option<&mut dyn QuicTimer> {
        None
    }

    fn h3_streams(&mut self) -> Option<&mut dyn H3Streams> {
        None
    }

    fn recv_room(&mut self) -> Option<&mut crate::conn::quic::RecvRoom> {
        None
    }
}

/// A layer that works on a connection's bytes (C's `Curl_cftype`): what
/// every piece of a connection answers of its life (`Part`), over the
/// layers below it, and the bytes both ways. Its `destroy` is `Drop`; its
/// `cntrl` codes are methods of their own.
pub(crate) trait Layer: for<'a> Part<Below<'a>> + Send + fmt::Debug {
    /// Read into `buf`, which is not empty, at most its length, from
    /// what it holds or from below.
    fn recv(&mut self, cx: &mut dyn LayerCx, below: Below<'_>, buf: &mut [u8]) -> io::Result<Recv>;

    /// Send from `bytes`, which is not empty, through the layers below.
    fn send(&mut self, cx: &mut dyn LayerCx, below: Below<'_>, bytes: &[u8]) -> io::Result<Sent>;

    /// Send what it holds that was taken to send, and what the layers
    /// below hold, as far as they take it (`CF_CTRL_FLUSH`): whether all
    /// of it went.
    fn flush(&mut self, cx: &mut dyn LayerCx, below: Below<'_>) -> io::Result<bool> {
        below.flush(cx)
    }

    /// The channel binding of the origin's TLS, if this layer is it:
    /// what its session binds with, or why it cannot (`Curl_conn_is_ssl`,
    /// which passes over an HTTPS proxy's, then `get_channel_binding`).
    fn channel_binding(
        &self,
        _notes: &mut dyn crate::tls::BindingNotes,
    ) -> Option<Result<Option<Vec<u8>>, ErrorKind>> {
        None
    }

    /// The latest session of the origin's TLS, if this layer is it and
    /// keeps a copy (`Curl_ssl_get_cf_session`).
    fn latest_session(&self) -> Option<&crate::tls::TlsTicket> {
        None
    }

    /// Move the goodbye of the origin's TLS on, as `goodbye` says, if this
    /// layer is it, its session called with no filter's trace around it
    /// (`vtls_shutdown_blocking`); none from any other layer.
    fn clear_tls(
        &mut self,
        _cx: &mut dyn LayerCx,
        _below: Below<'_>,
        _goodbye: crate::tls::Goodbye,
    ) -> Option<Result<Handshake, ErrorKind>> {
        None
    }
}

/// The layers below one, then the socket: the stack split at the layer
/// being called, so a layer reads and writes the ones below without
/// aliasing itself.
pub(crate) struct Below<'a> {
    /// Bottom first.
    layers: &'a mut [Box<dyn Layer>],
    socket: &'a dyn Socket,
    /// The socket's filter, when the socket's sends and receives are
    /// traced, and their failures said, as they reach it (`cf_socket_send`,
    /// `cf_socket_recv`); none when the caller says what it needs itself.
    traced: Option<Component>,
    /// Set as the socket first receives a byte (`got_first_byte`), where
    /// its stream keeps the fact.
    heard: Option<&'a Cell<bool>>,
}

impl<'a> Below<'a> {
    /// The layers `layers`, bottom first, over `socket`, for a test.
    #[cfg(test)]
    pub(crate) fn new(layers: &'a mut [Box<dyn Layer>], socket: &'a dyn Socket) -> Below<'a> {
        Below {
            layers,
            socket,
            traced: None,
            heard: None,
        }
    }
}

impl<'a> Below<'a> {
    /// No layers, straight over `socket`: a QUIC connection's datagrams
    /// dialed to its peer; the socket's sends and receives traced as
    /// `traced`, if given.
    pub(crate) fn bare(socket: &'a dyn Socket, traced: Option<Component>) -> Below<'a> {
        Below {
            layers: &mut [],
            socket,
            traced,
            heard: None,
        }
    }
}

impl Below<'_> {
    /// The same layers and socket, for one call that leaves them to the
    /// caller after.
    /// The socket under the layers: what a QUIC connection sends and
    /// reads its datagrams through, the bottom layer's own.
    pub(crate) fn socket(&self) -> &dyn Socket {
        self.socket
    }

    /// What the topmost of these layers that failed of its own failed
    /// with, if one did: a call through them that failed fails with it,
    /// as C passes on a lower filter's result.
    pub(crate) fn failure(&self) -> Option<ErrorKind> {
        self.layers
            .iter()
            .rev()
            .find_map(|layer| match layer.query(LayerQuery::Failure) {
                Some(LayerAnswer::Failure(kind)) => Some(kind),
                _ => None,
            })
    }

    pub(crate) fn reborrow(&mut self) -> Below<'_> {
        Below {
            layers: &mut *self.layers,
            socket: self.socket,
            traced: self.traced,
            heard: self.heard,
        }
    }

    pub(crate) fn recv(self, cx: &mut dyn LayerCx, buf: &mut [u8]) -> io::Result<Recv> {
        match self.layers.split_last_mut() {
            Some((top, layers)) => top.recv(cx, Below { layers, ..self }, buf),
            None => {
                let got = self.socket.recv(buf);
                if let Err(e) = &got {
                    cx.socket_failed(e);
                }
                if let (Ok(Recv::Data(_)), Some(heard)) = (&got, self.heard) {
                    heard.set(true);
                }
                if let Some(component) = self.traced {
                    let (code, n) = match &got {
                        Ok(Recv::Data(n)) => (0, n.get()),
                        Ok(Recv::Eof) => (0, 0),
                        Ok(Recv::WouldBlock) => (AGAIN_NUMBER, 0),
                        Err(e) => {
                            let why = curl_os::error::ErrorText::of(e);
                            let kind = ErrorKind::RecvError;
                            cx.fails_with(kind, &[b"Recv failure: ", why.as_bytes()]);
                            (kind.number(), 0)
                        }
                    };
                    let len = buf.len();
                    cx.of(component, format_args!("recv(len={len}) -> {code}, {n}"));
                }
                got
            }
        }
    }

    pub(crate) fn send(self, cx: &mut dyn LayerCx, bytes: &[u8]) -> io::Result<Sent> {
        match self.layers.split_last_mut() {
            Some((top, layers)) => top.send(cx, Below { layers, ..self }, bytes),
            None => {
                let sent = self.socket.send(bytes);
                if let Err(e) = &sent {
                    cx.socket_failed(e);
                }
                if let Some(component) = self.traced {
                    let (code, n) = match &sent {
                        Ok(Sent::Bytes(n)) => (0, n.get()),
                        Ok(Sent::WouldBlock) => (AGAIN_NUMBER, 0),
                        Err(e) => {
                            let why = curl_os::error::ErrorText::of(e);
                            let kind = ErrorKind::SendError;
                            cx.fails_with(kind, &[b"Send failure: ", why.as_bytes()]);
                            (kind.number(), 0)
                        }
                    };
                    let len = bytes.len();
                    cx.of(component, format_args!("send(len={len}) -> {code}, {n}"));
                }
                sent
            }
        }
    }

    /// Send what the layers hold to send (`Curl_conn_flush`): whether
    /// all of it went. The socket holds nothing.
    pub(crate) fn flush(self, cx: &mut dyn LayerCx) -> io::Result<bool> {
        match self.layers.split_last_mut() {
            Some((top, layers)) => top.flush(cx, Below { layers, ..self }),
            None => Ok(true),
        }
    }

    /// The socket holds nothing a poll cannot see.
    pub(crate) fn data_pending(self) -> bool {
        match self.layers.split_last_mut() {
            Some((top, layers)) => top.data_pending(Below { layers, ..self }),
            None => false,
        }
    }

    /// The socket polled at once for anything to read, priority and
    /// urgent data among it (`cf_socket_conn_is_alive`).
    pub(crate) fn alive(self, cx: &mut dyn LayerCx) -> Alive {
        match self.layers.split_last_mut() {
            Some((top, layers)) => top.is_alive(cx, Below { layers, ..self }),
            None => {
                let asked = Events::RDNORM | Events::IN | Events::RDBAND | Events::PRI;
                let mut watch = [SocketPoll::new(self.socket, asked)];
                let polled = poll_together(&mut watch, &mut [], Duration::ZERO);
                alive_of(polled.map(|_| watch[0].revents()))
            }
        }
    }
}

impl Lower for Below<'_> {
    fn data_pending(self) -> bool {
        Below::data_pending(self)
    }

    fn alive(self, cx: &mut dyn LayerCx) -> Alive {
        Below::alive(self, cx)
    }
}

/// What a poll of the socket for input says of the connection: a failed
/// poll, an error, a hang-up, urgent data or a bad descriptor is dead;
/// nothing at all is alive; anything else is input pending
/// (`cf_socket_conn_is_alive`).
fn alive_of(revents: io::Result<Events>) -> Alive {
    let dead = Events::ERR | Events::HUP | Events::PRI | Events::NVAL;
    match revents {
        Err(_) => Alive::Dead,
        Ok(r) if r.is_empty() => Alive::Alive {
            input_pending: false,
        },
        Ok(r) if r.intersects(dead) => Alive::Dead,
        Ok(_) => Alive::Alive {
            input_pending: true,
        },
    }
}

/// A stream's layers that work on its bytes, bottom first. Empty, it
/// allocates nothing; it is held by one pointer, as the first layer,
/// TLS's, is rare.
#[derive(Debug, Default)]
pub(crate) struct LayerStack {
    #[expect(clippy::box_collection, reason = "one pointer in every connection")]
    layers: Option<Box<Vec<Box<dyn Layer>>>>,
}

impl LayerStack {
    /// The stack over `socket`, from its top; the socket's sends and
    /// receives traced as `traced`, if given.
    pub(crate) fn over<'a>(
        &'a mut self,
        socket: &'a dyn Socket,
        traced: Option<Component>,
        heard: Option<&'a Cell<bool>>,
    ) -> Below<'a> {
        Below {
            layers: self
                .layers
                .as_deref_mut()
                .map_or(&mut [], Vec::as_mut_slice),
            socket,
            traced,
            heard,
        }
    }

    /// Put `layer` on top.
    pub(crate) fn push(&mut self, layer: Box<dyn Layer>) -> Result<(), OutOfMemory> {
        let layers = match &mut self.layers {
            Some(layers) => layers,
            None => self.layers.insert(try_box(Vec::new())?),
        };
        layers.try_push(layer)
    }

    /// Move the top layer's handshake on over the layers below it and
    /// `socket`, as the setup adds and connects one filter at a time;
    /// with no layer, there is none to make.
    pub(crate) fn connect(
        &mut self,
        socket: &dyn Socket,
        cx: &mut dyn LayerCx,
        traced: Option<Component>,
        heard: Option<&Cell<bool>>,
    ) -> Result<Handshake, ErrorKind> {
        let below = self.over(socket, traced, heard);
        match below.layers.split_last_mut() {
            Some((top, layers)) => top.connect(cx, Below { layers, ..below }),
            None => Ok(Handshake::Done),
        }
    }

    /// What the transfer is to wait for, given what it wants, each layer
    /// adjusting it from the top down (`Curl_conn_cf_adjust_pollset`).
    pub(crate) fn adjust_pollset(&self, wanted: Events) -> Events {
        self.layers
            .iter()
            .flat_map(|l| l.iter())
            .rev()
            .fold(wanted, |wanted, layer| layer.adjust_pollset(wanted))
    }

    /// The answer of the topmost layer that answers `q`.
    pub(crate) fn query(&self, q: LayerQuery) -> Option<LayerAnswer> {
        self.layers
            .iter()
            .flat_map(|l| l.iter())
            .rev()
            .find_map(|layer| layer.query(q))
    }

    /// The channel binding of the origin's TLS, if a layer is it.
    pub(crate) fn channel_binding(
        &self,
        notes: &mut dyn crate::tls::BindingNotes,
    ) -> Option<Result<Option<Vec<u8>>, ErrorKind>> {
        self.layers
            .iter()
            .flat_map(|l| l.iter())
            .rev()
            .find_map(|layer| layer.channel_binding(notes))
    }

    /// The latest session of the origin's TLS, if a layer is it and keeps
    /// a copy.
    pub(crate) fn latest_session(&self) -> Option<&crate::tls::TlsTicket> {
        self.layers
            .iter()
            .flat_map(|l| l.iter())
            .rev()
            .find_map(|layer| layer.latest_session())
    }

    /// Move the goodbye of the origin's TLS on over `socket`, as
    /// `goodbye` says, and take its layer off once it is over or failed,
    /// the bytes above it then going to the socket in clear
    /// (`Curl_ssl_cfilter_remove`); with no such layer, there is nothing
    /// to clear.
    pub(crate) fn clear_tls(
        &mut self,
        socket: &dyn Socket,
        cx: &mut dyn LayerCx,
        traced: Option<Component>,
        heard: Option<&Cell<bool>>,
        goodbye: crate::tls::Goodbye,
    ) -> Result<Handshake, ErrorKind> {
        let Some(layers) = self.layers.as_deref_mut() else {
            return Ok(Handshake::Done);
        };
        for at in (0..layers.len()).rev() {
            let (below, top) = layers.split_at_mut(at);
            let below = Below {
                layers: below,
                socket,
                traced,
                heard,
            };
            let Some(r) = top[0].clear_tls(cx, below, goodbye) else {
                continue;
            };
            if r != Ok(Handshake::Waiting) {
                drop(layers.remove(at));
            }
            return r;
        }
        Ok(Handshake::Done)
    }

    /// Shut its layers down over `socket` from the top, past the `shut`
    /// done already, counting each that finishes: a layer starts once the
    /// one above is done (`Curl_cshutdn_try_once_idx`).
    pub(crate) fn shutdown(
        &mut self,
        socket: &dyn Socket,
        cx: &mut dyn LayerCx,
        shut: &mut usize,
    ) -> Result<Handshake, ErrorKind> {
        let layers = self
            .layers
            .as_deref_mut()
            .map_or(&mut [][..], Vec::as_mut_slice);
        while *shut < layers.len() {
            let (below, top) = layers.split_at_mut(layers.len() - 1 - *shut);
            let below = Below {
                layers: below,
                socket,
                traced: None,
                heard: None,
            };
            // Each layer's end said in its name (`Curl_cshutdn_try_once_idx`).
            let filter = top[0].filter();
            let said = |cx: &mut dyn LayerCx, line: fmt::Arguments<'_>| {
                if let Some(filter) = filter {
                    cx.of(filter, line);
                }
            };
            match top[0].shutdown(cx, below) {
                Ok(Handshake::Waiting) => {
                    said(cx, format_args!("shut down not done yet"));
                    return Ok(Handshake::Waiting);
                }
                Ok(Handshake::Done) => said(cx, format_args!("shut down successfully")),
                Err(kind) => {
                    let code = kind.number();
                    said(cx, format_args!("shut down failed with {code}"));
                    return Err(kind);
                }
            }
            *shut += 1;
        }
        Ok(Handshake::Done)
    }

    /// What the layers not shut down yet wait on, `shut` from the top
    /// being done: each says, from the top, with nothing wanted to start
    /// from; a layer shut down says nothing (`Curl_conn_cf_adjust_pollset`).
    pub(crate) fn shutdown_pollset(&self, shut: usize) -> Events {
        self.layers
            .iter()
            .flat_map(|l| l.iter())
            .rev()
            .skip(shut)
            .fold(Events::NONE, |wanted, layer| layer.adjust_pollset(wanted))
    }

    /// Say, as `shutdown_pollset` asks them, what the layers not shut
    /// down yet put in for socket `fd`, as C's filters trace it.
    pub(crate) fn say_shutdown_pollset(&self, shut: usize, fd: i32, cx: &mut dyn LayerCx) {
        for layer in self.layers.iter().flat_map(|l| l.iter()).rev().skip(shut) {
            if let (Some(events), Some(filter)) = (layer.pollset_said(), layer.filter()) {
                let way = if events.contains(Events::OUT) {
                    "POLLOUT"
                } else {
                    "POLLIN"
                };
                cx.of(filter, format_args!("adjust_pollset, {way} fd={fd}"));
            }
        }
    }
}

/// How a connection's `Lingering` layer shuts down.
#[cfg(any(test, feature = "test-util"))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Linger {
    /// It waits this many tries, then is done.
    Passes(u32),
    /// It waits until its peer sends something or closes.
    UntilPeer,
}

/// A layer whose shutdown waits, as TLS's does for the peer's
/// close_notify: what arms a closing connection before TLS can. It passes
/// the bytes, and while it shuts down waits to read and sends nothing.
#[cfg(any(test, feature = "test-util"))]
#[derive(Debug)]
pub(crate) struct Lingering {
    how: Linger,
    shutting: bool,
}

#[cfg(any(test, feature = "test-util"))]
impl Lingering {
    pub(crate) fn boxed(how: Linger) -> Result<Box<dyn Layer>, OutOfMemory> {
        Ok(try_box(Lingering {
            how,
            shutting: false,
        })?)
    }
}

#[cfg(any(test, feature = "test-util"))]
impl Part<Below<'_>> for Lingering {
    fn adjust_pollset(&self, wanted: Events) -> Events {
        if self.shutting {
            wanted | Events::IN
        } else {
            wanted
        }
    }

    fn shutdown(&mut self, cx: &mut dyn LayerCx, below: Below<'_>) -> Result<Handshake, ErrorKind> {
        self.shutting = true;
        match &mut self.how {
            Linger::Passes(0) => Ok(Handshake::Done),
            Linger::Passes(n) => {
                *n -= 1;
                Ok(Handshake::Waiting)
            }
            Linger::UntilPeer => match below.recv(cx, &mut [0u8; 64]) {
                Ok(Recv::WouldBlock) => Ok(Handshake::Waiting),
                Ok(Recv::Data(_) | Recv::Eof) => Ok(Handshake::Done),
                Err(_) => Err(ErrorKind::RecvError),
            },
        }
    }
}

#[cfg(any(test, feature = "test-util"))]
impl Layer for Lingering {
    fn recv(&mut self, cx: &mut dyn LayerCx, below: Below<'_>, buf: &mut [u8]) -> io::Result<Recv> {
        below.recv(cx, buf)
    }

    /// Nothing more goes once it shuts down, as nothing goes over TLS
    /// after its close_notify.
    fn send(&mut self, cx: &mut dyn LayerCx, below: Below<'_>, bytes: &[u8]) -> io::Result<Sent> {
        if self.shutting {
            return Err(io::ErrorKind::BrokenPipe.into());
        }
        below.send(cx, bytes)
    }
}

/// Layers for the tests of what the stack asks of its layers.
#[cfg(test)]
pub(crate) mod testing {
    use super::*;

    /// Passes the bytes, and asks to write whenever the transfer waits,
    /// as TLS does with bytes to flush.
    #[derive(Debug)]
    pub(crate) struct WantsOut;

    pub(crate) fn wants_out() -> Box<dyn Layer> {
        try_box(WantsOut).unwrap()
    }

    impl Part<Below<'_>> for WantsOut {
        fn adjust_pollset(&self, wanted: Events) -> Events {
            wanted | Events::OUT
        }
    }

    impl Layer for WantsOut {
        fn recv(
            &mut self,
            cx: &mut dyn LayerCx,
            below: Below<'_>,
            buf: &mut [u8],
        ) -> io::Result<Recv> {
            below.recv(cx, buf)
        }

        fn send(
            &mut self,
            cx: &mut dyn LayerCx,
            below: Below<'_>,
            bytes: &[u8],
        ) -> io::Result<Sent> {
            below.send(cx, bytes)
        }
    }

    /// Makes the letters it passes upper case, both ways.
    #[derive(Debug)]
    pub(crate) struct Upper;

    pub(crate) fn upper() -> Box<dyn Layer> {
        try_box(Upper).unwrap()
    }

    impl Part<Below<'_>> for Upper {}

    impl Layer for Upper {
        fn recv(
            &mut self,
            cx: &mut dyn LayerCx,
            below: Below<'_>,
            buf: &mut [u8],
        ) -> io::Result<Recv> {
            let got = below.recv(cx, buf)?;
            if let Recv::Data(n) = got {
                buf[..n.get()].make_ascii_uppercase();
            }
            Ok(got)
        }

        fn send(
            &mut self,
            cx: &mut dyn LayerCx,
            below: Below<'_>,
            bytes: &[u8],
        ) -> io::Result<Sent> {
            let mut upper = [0u8; 4096];
            let n = bytes.len().min(upper.len());
            upper[..n].copy_from_slice(&bytes[..n]);
            upper[..n].make_ascii_uppercase();
            below.send(cx, &upper[..n])
        }
    }

    /// Reads what is below, and gives it only at the next read: the read
    /// that took it would block, as TLS's may with a record half read.
    #[derive(Debug, Default)]
    pub(crate) struct Holdback {
        held: Vec<u8>,
    }

    pub(crate) fn holdback() -> Box<dyn Layer> {
        try_box(Holdback::default()).unwrap()
    }

    impl Part<Below<'_>> for Holdback {
        fn data_pending(&self, below: Below<'_>) -> bool {
            !self.held.is_empty() || below.data_pending()
        }
    }

    impl Layer for Holdback {
        fn recv(
            &mut self,
            cx: &mut dyn LayerCx,
            below: Below<'_>,
            buf: &mut [u8],
        ) -> io::Result<Recv> {
            if let Some(n) = std::num::NonZeroUsize::new(self.held.len().min(buf.len())) {
                buf[..n.get()].copy_from_slice(&self.held[..n.get()]);
                self.held.drain(..n.get());
                return Ok(Recv::Data(n));
            }
            let got = below.recv(cx, buf)?;
            match got {
                Recv::Data(n) => {
                    self.held.try_extend_from_slice(&buf[..n.get()]).unwrap();
                    Ok(Recv::WouldBlock)
                }
                Recv::Eof | Recv::WouldBlock => Ok(got),
            }
        }

        fn send(
            &mut self,
            cx: &mut dyn LayerCx,
            below: Below<'_>,
            bytes: &[u8],
        ) -> io::Result<Sent> {
            below.send(cx, bytes)
        }
    }

    /// A `Holdback` holding `bytes` already.
    pub(crate) fn holding(bytes: &[u8]) -> Box<dyn Layer> {
        try_box(Holdback {
            held: bytes.to_vec(),
        })
        .unwrap()
    }

    /// Passes the bytes, and says the connection is dead.
    #[derive(Debug)]
    pub(crate) struct Dying;

    pub(crate) fn dying() -> Box<dyn Layer> {
        try_box(Dying).unwrap()
    }

    impl Part<Below<'_>> for Dying {
        fn is_alive(&mut self, _: &mut dyn LayerCx, _: Below<'_>) -> Alive {
            Alive::Dead
        }
    }

    impl Layer for Dying {
        fn recv(
            &mut self,
            cx: &mut dyn LayerCx,
            below: Below<'_>,
            buf: &mut [u8],
        ) -> io::Result<Recv> {
            below.recv(cx, buf)
        }

        fn send(
            &mut self,
            cx: &mut dyn LayerCx,
            below: Below<'_>,
            bytes: &[u8],
        ) -> io::Result<Sent> {
            below.send(cx, bytes)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::testing::{holdback, holding, upper};
    use super::*;
    use crate::conn::io::{Conversation, FakeNet, Peer};
    use crate::time::{Clock as _, ManualClock};

    /// A socket of the fake network's to a peer that does as `peer` says,
    /// holding `talk` if it accepts.
    fn socket(peer: Peer, talk: &Conversation) -> (Box<dyn Socket>, Silent) {
        let clock = ManualClock::new().unwrap();
        let at = std::net::SocketAddr::from(([127, 0, 0, 1], 1));
        let mut net = FakeNet::new(clock.clone())
            .with_peer(at, peer)
            .with_conversation(at, talk.clone());
        (crate::conn::io::dial(&mut net, at), Silent(clock.now()))
    }

    /// The socket at the bottom is polled as `cf_socket_conn_is_alive`
    /// polls it: nothing is alive; something to read alone is input
    /// pending; an error or a hang-up is dead, whatever else is there.
    #[test]
    fn the_socket_says_whether_the_connection_is_alive() {
        let talk = Conversation::replies(&[b"x"], false).per_send();
        let (s, mut cx) = socket(Peer::Accepts, &talk);
        let below = || Below {
            layers: &mut [],
            socket: &*s,
            traced: None,
            heard: None,
        };
        assert_eq!(
            below().alive(&mut cx),
            Alive::Alive {
                input_pending: false
            }
        );
        below().send(&mut cx, b"hello").unwrap();
        assert_eq!(
            below().alive(&mut cx),
            Alive::Alive {
                input_pending: true
            }
        );
        let (refused, mut cx) = socket(Peer::Refuses, &talk);
        let below = Below {
            layers: &mut [],
            socket: &*refused,
            traced: None,
            heard: None,
        };
        assert_eq!(below.alive(&mut cx), Alive::Dead);
    }

    /// A socket that is ready for `0` now, and polls as nothing else.
    #[derive(Debug)]
    struct Ready(Events);

    impl Socket for Ready {
        fn key(&self) -> crate::conn::io::SocketKey {
            crate::conn::io::SocketKey::new(3)
        }
        fn readiness(&self) -> crate::conn::io::Readiness<'_> {
            crate::conn::io::Readiness::Known {
                now: self.0,
                later: None,
            }
        }
        fn take_error(&self) -> io::Result<Option<io::Error>> {
            unreachable!()
        }
        fn local_addr(&self) -> io::Result<std::net::SocketAddr> {
            unreachable!()
        }
        fn set(&self, _: crate::conn::io::SocketOption) -> io::Result<()> {
            unreachable!()
        }
        fn set_nonblocking(&self) -> io::Result<()> {
            unreachable!()
        }
        fn bind(&self, _: std::net::SocketAddr) -> io::Result<()> {
            unreachable!()
        }
        fn bind_to_device(&self, _: &[u8]) -> io::Result<()> {
            unreachable!()
        }
        fn connect(&self, _: &crate::conn::io::Remote) -> io::Result<crate::conn::io::Connect> {
            unreachable!()
        }
        fn recv(&self, _: &mut [u8]) -> io::Result<Recv> {
            unreachable!()
        }
        fn send(&self, _: &[u8]) -> io::Result<Sent> {
            unreachable!()
        }
        fn release(self: Box<Self>) -> crate::conn::io::SocketKey {
            unreachable!()
        }
    }

    /// The health check asks for urgent and priority data as well as
    /// normal data, as C's does: urgent data, as TCP's out-of-band byte,
    /// is dead; priority band data alone, or normal data said both ways,
    /// is input pending (`cf_socket_conn_is_alive`).
    #[test]
    fn urgent_data_is_dead_and_any_other_input_pending() {
        let alive = |ready: Events| {
            let s = Ready(ready);
            let below = Below {
                layers: &mut [],
                socket: &s,
                traced: None,
                heard: None,
            };
            below.alive(&mut Silent(ManualClock::new().unwrap().now()))
        };
        let pending = Alive::Alive {
            input_pending: true,
        };
        assert_eq!(alive(Events::PRI), Alive::Dead);
        assert_eq!(alive(Events::IN | Events::PRI), Alive::Dead);
        assert_eq!(alive(Events::RDBAND), pending);
        assert_eq!(alive(Events::IN | Events::RDNORM), pending);
        assert_eq!(alive(Events::RDNORM), pending);
        assert_eq!(alive(Events::IN | Events::HUP), Alive::Dead);
        assert_eq!(alive(Events::NVAL), Alive::Dead);
        // Ready only to send is asked nothing of.
        assert_eq!(
            alive(Events::OUT),
            Alive::Alive {
                input_pending: false
            }
        );
        assert_eq!(alive_of(Err(io::ErrorKind::Other.into())), Alive::Dead);
    }

    /// A real socket with bytes to read is input pending: the kernel says
    /// `IN` and `RDNORM` together once both are asked.
    #[test]
    fn a_real_socket_with_bytes_to_read_is_input_pending() {
        use std::io::Write as _;
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let at = listener.local_addr().unwrap();
        let socket = curl_os::net::open(at, curl_os::net::Protocol::Tcp, true).unwrap();
        socket.connect(at).unwrap();
        let (mut peer, _) = listener.accept().unwrap();
        let below = || Below {
            layers: &mut [],
            socket: &socket,
            traced: None,
            heard: None,
        };
        let mut cx = Silent(ManualClock::new().unwrap().now());
        assert_eq!(
            below().alive(&mut cx),
            Alive::Alive {
                input_pending: false
            }
        );
        peer.write_all(b"x").unwrap();
        // Loopback delivers before the write returns; the poll is at once.
        assert_eq!(
            below().alive(&mut cx),
            Alive::Alive {
                input_pending: true
            }
        );
    }

    /// A layer that keeps the defaults passes the question below: the
    /// pollset as it is wanted, and data pending as the layers below hold
    /// it.
    #[test]
    fn a_layer_s_defaults_ask_below() {
        let talk = Conversation::replies(&[], false);
        let (s, _) = socket(Peer::Accepts, &talk);
        assert_eq!(upper().adjust_pollset(Events::IN), Events::IN);
        let mut holds = [holding(b"x"), upper()];
        let below = Below {
            layers: &mut holds,
            socket: &*s,
            traced: None,
            heard: None,
        };
        assert!(below.data_pending());
        let mut empty = [holdback(), upper()];
        let below = Below {
            layers: &mut empty,
            socket: &*s,
            traced: None,
            heard: None,
        };
        assert!(!below.data_pending());
    }
}
