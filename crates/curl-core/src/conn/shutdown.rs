//! Connections shutting down (`lib/cshutdn.c`): those whose layers say
//! goodbye to the peer over more than one pass, as TLS's close_notify may,
//! or whose protocol's goodbye awaits an answer, as FTP's `QUIT` does.
//! The multi's `ShutdownSet` is the one owner of each until it is closed,
//! whichever pool it left, a share's included: the releasing transfer's
//! multi takes it (conncache.c:242).
//!
//! Every connection leaving a pool goes through one discard
//! (`cpool_discard_conn`): an aborted transfer's is closed at once, as a
//! shutdown would tell the server the transfer succeeded; any other gets
//! one try, and is closed if that finishes, or else kept here, until its
//! layers are done or its time runs out. What happens here is traced on
//! the multi's internal trace, as C's `[SHUTDOWN]` lines are on its
//! internal handle.

use std::num::NonZeroU32;
use std::time::Duration;

use curl_alloc::TryVec as _;

use super::io::{Events, Net, Socket, SocketKey, SocketPoll};
use super::layer::Handshake;
use super::line::Goodbye;
use super::{Conn, Peer, Route, Transport};
use crate::components::Component;
use crate::conn::quic::RecvRoom;
use crate::proto::pingpong::drive::BLOCKING_POLL;
use crate::time::{Instant, SharedClock};
use crate::trace::{Internal, InternalCx};

/// What a connection keeps of its creating transfer's settings for the
/// time after it, as C's internal handle copies the last caller's
/// (`Curl_get_admin`): captured per connection as the pool adds it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ConnSettings {
    /// How long its shutdown may take, in milliseconds. No option sets
    /// it (`set.shutdowntimeout` is set by none), so it is always C's
    /// `DEFAULT_SHUTDOWN_TIMEOUT_MS`.
    shutdown_ms: u32,
    /// Its connect bound the socket to an address or a port (`bits.bound`).
    bound_local: bool,
}

impl ConnSettings {
    /// What a transfer's connections keep: the defaults, as no option
    /// changes them.
    pub(crate) const DEFAULT: ConnSettings = ConnSettings {
        shutdown_ms: 2000,
        bound_local: false,
    };

    /// Whether its connect bound the socket to an address or a port.
    pub(crate) fn bound_local(self) -> bool {
        self.bound_local
    }

    pub(crate) fn set_bound_local(&mut self, bound: bool) {
        self.bound_local = bound;
    }

    /// How long a shutdown may take.
    pub(crate) fn shutdown_time(self) -> Duration {
        Duration::from_millis(u64::from(self.shutdown_ms))
    }
}

/// A connection in a closing set, and how far its shutdown got.
#[derive(Debug)]
pub(crate) struct Shutting {
    conn: Conn,
    /// Its layers already shut down, counted from the top: the shutdown
    /// goes down the stack, a layer's starting once the one above is done
    /// (`Curl_cshutdn_try_once_idx`).
    shut: usize,
    /// When the shutdown started, in milliseconds after the connection
    /// was created as C counts them (C's `shutdown.start_ms`).
    started_ms: i64,
    /// It was tried once at least: its start was said.
    tried: bool,
    /// Its protocol said goodbye, or was told the connection is dead
    /// (`bits.shutdown_handler`): asked once, whatever comes after.
    said: bool,
    /// Its protocol's goodbye awaits an answer, which C's blocking
    /// disconnect waits for before the layers shut down (`ftp_quit`):
    /// the shutdown waits for it, in its own time, until this instant
    /// unless more of it comes (`BLOCKING_POLL`).
    answer_due: Option<Instant>,
    /// A try finished it, its layers done, failed or out of time
    /// (`bits.shutdown_filters`): its close is no forced one.
    finished: bool,
    /// It is closed once its goodbye is answered, its layers given one
    /// try, as C closes a connection a share's pool evicts
    /// (`Curl_cshutdn_terminate` with `do_shutdown`): it waits in a set
    /// only for the answer, which C blocks for.
    once: bool,
}

/// What one try of a shutdown came to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Tried {
    /// Finished, or failed, or out of time: the connection is to close.
    Done,
    /// Its layers wait for the socket.
    Waiting,
    /// Its layers wait, but it closes all the same, unfinished (`once`):
    /// what a try says only within, as `Done`.
    Cut,
}

impl Shutting {
    /// The shutdown of `conn` starts at `now` (`Curl_cshutdn_start_timer`).
    pub(crate) fn start(conn: Conn, now: Instant) -> Shutting {
        let started_ms = now.ms_since(conn.created);
        Shutting {
            conn,
            shut: 0,
            started_ms,
            tried: false,
            said: false,
            answer_due: None,
            finished: false,
            once: false,
        }
    }

    /// Whether its protocol's goodbye awaits an answer.
    fn awaits(&self) -> bool {
        self.answer_due.is_some()
    }

    /// Wait here for the answer its protocol's goodbye awaits, if it awaits
    /// one, polling its socket alone, as C's disconnect blocks for it
    /// (`Curl_pp_statemach` blocking): until it comes, or a second passes
    /// with nothing more of it, or the shutdown's time is spent, or a poll
    /// fails. The time is `clock`'s, read after each poll. Allocates
    /// nothing, so a connection that could not be kept for want of memory
    /// is waited for too; a read that cannot hold what came ends the wait.
    fn await_answer(&mut self, net: &mut dyn Net, clock: &SharedClock, trace: Option<&Internal>) {
        loop {
            let now = clock.now();
            let mut cx = InternalCx {
                now,
                trace,
                room: None,
            };
            if self.left_ms(now) < 0 || !self.awaits_answer(&mut cx) {
                return;
            }
            let (Some(left), Some((socket, events))) = (self.answer_time_left(now), self.pollset())
            else {
                return;
            };
            let mut polls = [SocketPoll::new(socket, events)];
            if net.poll(&mut polls, &mut [], left).is_err() {
                return;
            }
        }
    }

    /// Its protocol's goodbye, unless said already
    /// (`cshutdn_run_conn_handler`); `dead` if no one knows what state
    /// the connection is in. Whether it was said now.
    fn say_goodbye(&mut self, cx: &mut InternalCx<'_>, dead: bool) -> bool {
        if std::mem::replace(&mut self.said, true) {
            return false;
        }
        let (trace, now) = (cx.trace, cx.now);
        self.answer_due = match self.conn.protocol_goodbye(cx, trace, dead) {
            Goodbye::Done => None,
            Goodbye::Awaited { .. } => Some(now.after(BLOCKING_POLL)),
        };
        true
    }

    /// Whether its protocol's goodbye still awaits an answer, read on as
    /// far as the connection lets it now: no longer once a poll of C's
    /// blocking drive (`BLOCKING_POLL`) passed with none of it, as C's
    /// gives up on one that found nothing as a connection disconnects
    /// (`Curl_pp_statemach`).
    fn awaits_answer(&mut self, cx: &mut InternalCx<'_>) -> bool {
        let Some(due) = self.answer_due else {
            return false;
        };
        let now = cx.now;
        self.answer_due = match self.conn.goodbye_answer(cx) {
            Goodbye::Done => None,
            Goodbye::Awaited { moved: true } => Some(now.after(BLOCKING_POLL)),
            Goodbye::Awaited { moved: false } => (now < due).then_some(due),
        };
        self.answer_due.is_some()
    }

    /// The time left for the answer its protocol's goodbye awaits, if it
    /// awaits one: until it is due, within the shutdown's time.
    fn answer_time_left(&self, now: Instant) -> Option<Duration> {
        let left = Duration::from_millis(self.left_ms(now).max(0).unsigned_abs());
        self.answer_due.map(|due| due.since(now).min(left))
    }

    /// Milliseconds left at `now` of the shutdown's time, -1 for none
    /// (`Curl_cshutdn_timeleft_ms`, whose 0 means no limit).
    fn left_ms(&self, now: Instant) -> i64 {
        let limit = i64::from(self.conn.settings.shutdown_ms);
        let spent = now
            .ms_since(self.conn.created)
            .saturating_sub(self.started_ms);
        match limit.saturating_sub(spent) {
            0 => -1,
            left => left,
        }
    }

    /// Move the shutdown on once at `now` (`cshutdn_run_once`): out of
    /// time, it is done; else each layer from the top that is not shut
    /// down yet, then the socket's own, which reads and drops up to 1 KB
    /// so the kernel answers the peer's last bytes with no reset
    /// (`cf_socket_shutdown`). A layer that fails ends it. Said on
    /// `trace` as C's internal handle says it (`Curl_cshutdn_try_once`);
    /// a QUIC connection receives in `room`, the multi's, if the multi
    /// runs it.
    pub(crate) fn try_once(
        &mut self,
        now: Instant,
        trace: Option<&Internal>,
        room: Option<&mut RecvRoom>,
    ) -> Tried {
        let tried = match self.run_once(now, trace, room) {
            Tried::Done => {
                self.finished = true;
                Tried::Done
            }
            // C's terminate leaves its filters unfinished: a forced close.
            Tried::Cut => Tried::Done,
            Tried::Waiting => Tried::Waiting,
        };
        if let Some(t) = trace {
            let done = u8::from(tried == Tried::Done);
            t.of(
                Component::Multi,
                format_args!("[SHUTDOWN] shutdown, done={done}"),
            );
        }
        tried
    }

    fn run_once(
        &mut self,
        now: Instant,
        trace: Option<&Internal>,
        room: Option<&mut RecvRoom>,
    ) -> Tried {
        let mut cx = InternalCx { now, trace, room };
        if !std::mem::replace(&mut self.tried, true) {
            if let Some(t) = trace {
                t.of(
                    Component::Multi,
                    format_args!("shutdown start on connection"),
                );
            }
        } else if self.left_ms(now) < 0 {
            if let Some(t) = trace {
                t.info(format_args!("shutdown timeout"));
            }
            return Tried::Done;
        }
        // Its protocol says goodbye first, once; then a session, each try
        // (`cshutdn_run_once`, `cf_h2_shutdown`).
        let said_now = self.say_goodbye(&mut cx, false);
        // The answer goes before the layers shut down: closing a socket
        // with it unread, or before it comes, resets the connection, and
        // the peer may then lose what it had not read yet (Windows does).
        // A goodbye said now read on as far as it could already.
        let awaits = match said_now {
            true => self.answer_due.is_some(),
            false => self.awaits_answer(&mut cx),
        };
        if awaits {
            return Tried::Waiting;
        }
        self.conn.goodbye(&mut cx);
        let socket = self.conn.socket_component();
        match &mut self.conn.transport {
            Transport::Stream(stream) => match stream.shutdown(&mut cx, socket, &mut self.shut) {
                Ok(Handshake::Waiting) if self.once => Tried::Cut,
                Ok(Handshake::Waiting) => Tried::Waiting,
                Ok(Handshake::Done) | Err(_) => Tried::Done,
            },
            // A datagram socket is not drained: C reads the dangling bytes
            // off a TCP socket alone (`cf_socket_shutdown`).
            Transport::Datagram(_) => Tried::Done,
            Transport::Local => Tried::Done,
        }
    }

    /// Close it, whatever its layers were doing (`Curl_cshutdn_terminate`):
    /// once the answer its protocol's goodbye awaits is read, waiting here
    /// on `clock` as C's disconnect does, as a socket closed with the
    /// answer unread or still to come is reset, and the peer may lose the
    /// goodbye (Windows does); then only the socket closes, nothing more
    /// is read from it. With no clock (a pool's own tests) it does not
    /// wait. Said on `trace`, and, `in_multi`, that a transfer waiting for
    /// room may find some.
    pub(crate) fn close(
        mut self,
        net: &mut dyn Net,
        clock: Option<&SharedClock>,
        trace: Option<&Internal>,
        in_multi: bool,
    ) {
        if let Some(clock) = clock {
            self.await_answer(net, clock, trace);
        }
        terminate(self.conn, self.finished, net, trace, in_multi);
    }

    /// Close it at once as `close` does, its use unknown: its protocol,
    /// told so, says no goodbye (`Curl_cshutdn_terminate` of an aborted
    /// transfer's connection, `dead_connection`).
    fn abandon(
        mut self,
        now: Instant,
        net: &mut dyn Net,
        trace: Option<&Internal>,
        in_multi: bool,
    ) {
        let mut cx = InternalCx {
            now,
            trace,
            room: None,
        };
        let _said = self.say_goodbye(&mut cx, true);
        // Told it is dead, its protocol awaits nothing.
        self.close(net, None, trace, in_multi);
    }

    /// What it waits on while it shuts down: what its protocol's goodbye
    /// does while it awaits its answer, then what its layers not shut down
    /// yet say, from the top (`Curl_conn_adjust_pollset` on a chain in
    /// shutdown, its connected socket adding nothing).
    fn pollset(&self) -> Option<(&dyn Socket, Events)> {
        let Transport::Stream(stream) = &self.conn.transport else {
            return None;
        };
        if self.awaits() {
            let line = self.conn.line().expect("a goodbye awaits on a line");
            return Some((stream.socket(), line.goodbye_wants()));
        }
        let events = stream.shutdown_pollset(self.shut);
        (!events.is_empty()).then(|| (stream.socket(), events))
    }

    /// Its pollset said on `trace`, as C's chain says it when the admin
    /// handle asks it (`Curl_conn_adjust_pollset`).
    fn say_pollset(&self, now: Instant, trace: &Internal) {
        if let Transport::Stream(stream) = &self.conn.transport {
            let mut cx = InternalCx {
                now,
                trace: Some(trace),
                room: None,
            };
            stream.say_shutdown_pollset(self.shut, &mut cx);
        }
    }

    /// The peer it goes to, for the limits on connections to one host.
    fn destination(&self) -> Option<&Peer> {
        match &self.conn.route {
            Route::Net(tcp) => Some(tcp.destination()),
            Route::Local => None,
        }
    }
}

/// Close `conn` (`Curl_cshutdn_terminate`), said on `trace`: forced unless
/// its shutdown `finished`, its socket's close, and, `in_multi`, that a
/// transfer waiting for room may find some.
fn terminate(
    conn: Conn,
    finished: bool,
    net: &mut dyn Net,
    trace: Option<&Internal>,
    in_multi: bool,
) {
    if let Some(t) = trace {
        let force = if finished { "" } else { "force " };
        let n = conn.number.get();
        t.of(
            Component::Multi,
            format_args!("[SHUTDOWN] {force}closing connection #{n}"),
        );
    }
    let component = conn.socket_component();
    let socket = match conn.transport {
        Transport::Local => None,
        Transport::Stream(stream) => Some(stream.into_socket()),
        Transport::Datagram(datagrams) => Some(datagrams.into_socket()),
    };
    if let Some(socket) = socket {
        if let Some(t) = trace {
            let fd = socket.key().get();
            t.of(component, format_args!("destroy"));
            t.of(component, format_args!("cf_socket_close, fd={fd}"));
            // Said by a multi's (`Curl_multi_will_close`), not a share's.
            if in_multi {
                t.of(
                    Component::Multi,
                    format_args!("Curl_multi_will_close fd={fd}"),
                );
            }
        }
        net.close(socket);
    }
    if in_multi && let Some(t) = trace {
        t.of(
            Component::Multi,
            format_args!("[SHUTDOWN] trigger multi connchanged"),
        );
    }
}

/// A connection in a `ShutdownSet`, by the set's own number for it: a
/// connection that left its pool has no `ConnId` that still names it. A
/// number the set no longer holds names nothing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ClosingId(u64);

#[derive(Debug)]
struct Entry {
    id: ClosingId,
    shutting: Shutting,
    /// The socket callback was asked to watch what it waits on
    /// (`cshutdn_update_ev`), which is done once, as it joins.
    announced: bool,
}

/// A multi's connections shutting down, oldest first (`struct cshutdn`).
#[derive(Debug)]
pub(crate) struct ShutdownSet {
    conns: Vec<Entry>,
    /// The multi's clock, which a goodbye's answer is waited for on when
    /// a connection awaiting one must close at once.
    clock: SharedClock,
    next_id: u64,
    /// When the set is next to be driven: the earliest time left of its
    /// connections, as its last pass found it, armed only by a pass and
    /// kept until it comes (C's `EXPIRE_SHUTDOWN` on its internal
    /// handle).
    deadline: Option<Instant>,
    /// Something happened on one of its sockets, or its deadline came: it
    /// runs with the next dirty transfers, before them (the internal
    /// handle's dirty bit).
    dirty: bool,
    /// A connection of the multi's changed since the multi last looked
    /// (C's `recheckstate`, set by `Curl_multi_connchanged`): one of the
    /// set's, or one the multi closed at once, closed; or a transfer's
    /// step found one to multiplex, its server's stream limit changed or
    /// a GOAWAY came, or an upgrade it asked for was answered. The next
    /// step of a transfer says so and lets one waiting look again, as
    /// does the end of a pass. Kept here, where every connection the
    /// multi closes passes, as the multi's one note of it.
    changed: bool,
    /// The multi's internal trace, if it has one.
    trace: Option<Internal>,
}

/// How many times its cap (`max_shutdowns`) a set may hold, for the
/// connections in it whose protocol's goodbye awaits an answer. C reads
/// that answer before a connection joins its set, blocking the multi
/// (`ftp_quit` and the others, in the first `Curl_cshutdn_try_once`), so
/// its set never holds one; here such a connection waits in the set, and
/// C's cap closes the oldest that awaits nothing instead. Past this
/// bound, the oldest is closed after all, its answer read first by
/// blocking as C does: a server that holds its answers back can make the
/// multi keep no more sockets than this many times what C keeps for
/// shutdowns, which scales with the application's own limit
/// (`CURLMOPT_MAX_TOTAL_CONNECTIONS`) and is 256 with none. Each such
/// connection waits two seconds at most and holds at most 64 KB of its
/// answer (`GOODBYE_READ_MAX`).
pub(crate) const AWAITING_CAP_FACTOR: usize = 2;

/// How many connections a multi lets shut down at once, `pool` being the
/// connections its own pool holds: the total limit less those, 1 once
/// none is left, and with no limit a quarter of them, at least 128
/// (`cpool_discard_conn`).
pub(crate) fn max_shutdowns(max_total: Option<NonZeroU32>, pool: u32) -> usize {
    let pool = usize::try_from(pool).expect("a pool's size fits");
    match max_total.map(|m| usize::try_from(m.get()).expect("fits")) {
        Some(max) if pool < max => max - pool,
        Some(_) => 1,
        None => (pool / 4).max(128),
    }
}

impl ShutdownSet {
    /// An empty set of a multi reading `clock`.
    pub(crate) fn new(clock: SharedClock) -> ShutdownSet {
        ShutdownSet {
            conns: Vec::new(),
            clock,
            next_id: 0,
            deadline: None,
            dirty: false,
            changed: false,
            trace: None,
        }
    }

    /// The multi's clock.
    pub(crate) fn clock(&self) -> &SharedClock {
        &self.clock
    }

    /// Trace what happens here on `trace` from now on.
    pub(crate) fn trace_internally(&mut self, trace: Internal) {
        self.trace = Some(trace);
    }

    /// The multi's internal trace, if it has one.
    pub(crate) fn internal(&self) -> Option<&Internal> {
        self.trace.as_ref()
    }

    pub(crate) fn len(&self) -> usize {
        self.conns.len()
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.conns.is_empty()
    }

    /// Take `shutting` in, closing the oldest first if `max` are already
    /// here (`Curl_cshutdn_add`): the oldest whose goodbye awaits no
    /// answer, or, with every one awaiting, none until the set holds
    /// [`AWAITING_CAP_FACTOR`] times `max`, and then the oldest, once its
    /// answer is read. With no room for it, it is closed, its own answer
    /// read first.
    pub(crate) fn add(&mut self, shutting: Shutting, max: usize, net: &mut dyn Net) {
        let len = self.conns.len();
        if max <= len {
            let unawaited = self.conns.iter().position(|e| !e.shutting.awaits());
            let oldest = match unawaited {
                Some(i) => Some(i),
                None => (max.saturating_mul(AWAITING_CAP_FACTOR) <= len).then_some(0),
            };
            if let Some(i) = oldest {
                self.say(format_args!(
                    "[SHUTDOWN] discarding oldest shutdown connection due to shutdown limit of {max}"
                ));
                let entry = self.conns.remove(i);
                self.closed(entry, net);
            }
        }
        let n = shutting.conn.number.get();
        if self.conns.try_reserve(1).is_err() {
            self.say(format_args!("[SHUTDOWN] adding failed, discarding #{n}"));
            shutting.close(net, Some(&self.clock), self.trace.as_ref(), true);
            self.changed = true;
            return;
        }
        let id = ClosingId(self.next_id);
        self.next_id += 1;
        self.conns
            .try_push(Entry {
                id,
                shutting,
                announced: false,
            })
            .expect("room was made");
        let now = self.conns.len();
        self.say(format_args!(
            "[SHUTDOWN] added #{n} to shutdowns, now {now} conns in shutdown"
        ));
    }

    /// A line of the set's on its trace.
    fn say(&self, line: std::fmt::Arguments<'_>) {
        if let Some(t) = &self.trace {
            t.of(Component::Multi, line);
        }
    }

    /// Close up to `n` of the oldest, of those to `to` if given, to make
    /// room for a new connection (`Curl_cshutdn_close_oldest`); how many
    /// were. One whose protocol's goodbye awaits an answer is kept: it
    /// counts toward the limits until the answer comes, and the transfer
    /// needing the room waits for it, where C blocks for the answer
    /// before the connection is in its set.
    pub(crate) fn close_oldest(&mut self, to: Option<&Peer>, n: u32, net: &mut dyn Net) -> u32 {
        let mut closed = 0;
        let mut i = 0;
        while closed < n && i < self.conns.len() {
            let shutting = &self.conns[i].shutting;
            let goes = !shutting.awaits()
                && to.is_none_or(|to| shutting.destination().is_some_and(|d| d.same_bundle(to)));
            if goes {
                let entry = self.conns.remove(i);
                self.closed(entry, net);
                closed += 1;
            } else {
                i += 1;
            }
        }
        closed
    }

    /// How many are to `to` (`Curl_cshutdn_dest_count`).
    pub(crate) fn count_to(&self, to: &Peer) -> u32 {
        let n = self
            .conns
            .iter()
            .filter(|e| e.shutting.destination().is_some_and(|d| d.same_bundle(to)))
            .count();
        u32::try_from(n).expect("a set's size fits")
    }

    /// Move each shutdown on at `now` (`cshutdn_perform`), closing those
    /// done, and arm the set's deadline at the earliest time left of the
    /// others; a QUIC connection receives in the multi's `room`.
    pub(crate) fn perform(&mut self, net: &mut dyn Net, now: Instant, room: &mut RecvRoom) {
        if self.conns.is_empty() {
            return;
        }
        let n = self.conns.len();
        self.say(format_args!("[SHUTDOWN] perform on {n} connections"));
        let mut next_ms: i64 = 0;
        let mut i = 0;
        while i < self.conns.len() {
            let trace = self.trace.as_ref();
            if self.conns[i]
                .shutting
                .try_once(now, trace, Some(&mut *room))
                == Tried::Done
            {
                let entry = self.conns.remove(i);
                self.closed(entry, net);
                continue;
            }
            let mut ms = self.conns[i].shutting.left_ms(now);
            // An answer awaited is given up on when due, a whole
            // millisecond on at least, as it is not due yet.
            if let Some(d) = self.conns[i].shutting.answer_time_left(now) {
                let d = i64::try_from(d.as_micros().div_ceil(1000)).unwrap_or(i64::MAX);
                ms = ms.min(d.max(1));
            }
            if ms != 0 && (next_ms == 0 || ms < next_ms) {
                next_ms = ms;
            }
            i += 1;
        }
        if next_ms != 0 {
            // A shutdown exactly at its limit is due at once.
            let wait = Duration::from_millis(next_ms.max(0).unsigned_abs());
            self.deadline = Some(now.after(wait));
        }
    }

    /// Close every one at once (the end of `cshutdn_terminate_all`).
    pub(crate) fn close_all(&mut self, net: &mut dyn Net) {
        while !self.conns.is_empty() {
            let entry = self.conns.remove(0);
            self.closed(entry, net);
        }
    }

    /// Close `entry`, which has left the set, its goodbye's answer read
    /// first if it awaits one.
    fn closed(&mut self, entry: Entry, net: &mut dyn Net) {
        entry
            .shutting
            .close(net, Some(&self.clock), self.trace.as_ref(), true);
        self.changed = true;
    }

    /// Close the connection `id` names, if the set still holds it: the
    /// socket callback refused to watch it (`cshutdn_update_ev` failing).
    pub(crate) fn close_one(&mut self, id: ClosingId, net: &mut dyn Net) {
        if let Some(i) = self.conns.iter().position(|e| e.id == id) {
            let entry = self.conns.remove(i);
            let n = entry.shutting.conn.number.get();
            self.say(format_args!(
                "[SHUTDOWN] update events failed, discarding #{n}"
            ));
            self.closed(entry, net);
        }
    }

    /// The first connection that joined and was not announced yet, and
    /// what it waits on, marked announced: the socket callback is told
    /// once, as it joins.
    pub(crate) fn next_unannounced(&mut self) -> Option<(ClosingId, Option<(SocketKey, Events)>)> {
        let entry = self.conns.iter_mut().find(|e| !e.announced)?;
        entry.announced = true;
        let wants = entry
            .shutting
            .pollset()
            .map(|(s, events)| (s.key(), events));
        Some((entry.id, wants))
    }

    /// Connection `id`'s pollset said on the internal trace, as C asks
    /// its chain to tell the socket callback (`cshutdn_update_ev`).
    pub(crate) fn say_pollset_of(&self, id: ClosingId, now: Instant) {
        if let (Some(t), Some(e)) = (&self.trace, self.conns.iter().find(|e| e.id == id)) {
            e.shutting.say_pollset(now, t);
        }
    }

    /// Each connection's pollset said on the internal trace, oldest
    /// first, as C's admin handle asks each chain as a wait or `fdset`
    /// collects them (`Curl_cshutdn_add_pollfds`, `Curl_cshutdn_setfds`).
    pub(crate) fn say_pollsets(&self, now: Instant) {
        if let Some(t) = &self.trace {
            for e in &self.conns {
                e.shutting.say_pollset(now, t);
            }
        }
    }

    /// The least time left at `now` of those whose protocol's goodbye
    /// awaits an answer, if any does: C waits for it inside the protocol's
    /// disconnect, whatever time the cleanup gives its shutdowns.
    pub(crate) fn answer_time_left(&self, now: Instant) -> Option<Duration> {
        self.conns
            .iter()
            .filter_map(|e| e.shutting.answer_time_left(now))
            .min()
    }

    /// Each connection's socket and what it waits on, oldest first.
    pub(crate) fn pollsets(&self) -> impl Iterator<Item = (&dyn Socket, Events)> + '_ {
        self.conns.iter().filter_map(|e| e.shutting.pollset())
    }

    /// Whether it holds the connection `id` names.
    #[cfg(debug_assertions)]
    pub(crate) fn holds(&self, id: ClosingId) -> bool {
        self.conns.iter().any(|e| e.id == id)
    }

    /// When the set is next due to run, if armed.
    pub(crate) fn deadline(&self) -> Option<Instant> {
        self.deadline
    }

    /// Its deadline came by `now`: forget it (`add_next_timeout`).
    pub(crate) fn expire(&mut self, now: Instant) -> bool {
        if self.deadline.is_some_and(|at| at <= now) {
            self.deadline = None;
            return true;
        }
        false
    }

    pub(crate) fn mark_dirty(&mut self) {
        self.dirty = true;
    }

    pub(crate) fn is_dirty(&self) -> bool {
        self.dirty
    }

    /// It runs now: no longer dirty.
    pub(crate) fn take_dirty(&mut self) -> bool {
        std::mem::take(&mut self.dirty)
    }

    /// A connection of the multi's changed since last asked.
    pub(crate) fn take_changed(&mut self) -> bool {
        std::mem::take(&mut self.changed)
    }

    /// Whether a connection of the multi's changed since last asked,
    /// left to be asked again.
    pub(crate) fn changed(&self) -> bool {
        self.changed
    }

    /// Note that a connection of the multi's changed
    /// (`Curl_multi_connchanged`).
    pub(crate) fn conn_changed(&mut self) {
        self.changed = true;
    }
}

/// Where the connections leaving a pool go: closed through a network, and,
/// for one that shuts down slowly, kept in a multi's set if there is one.
/// A network alone keeps none: what does not finish in one try is closed,
/// as C does with no multi (a share's cleanup), once the answer its
/// protocol's goodbye awaits is read, on the clock the exits read.
pub(crate) trait Exits {
    fn parts(&mut self) -> (&mut dyn Net, Option<Linger<'_>>);

    /// The clock a goodbye's answer is waited for on, if any.
    fn clock(&self) -> Option<SharedClock>;

    /// The internal trace of a handle with no multi, if it traces: what
    /// goes through a multi is said on the multi's set's.
    fn internal(&self) -> Option<Internal> {
        None
    }
}

/// A network alone, in a pool's own tests: with no clock, a connection
/// whose goodbye awaits an answer closes without it.
#[cfg(test)]
impl<N: Net> Exits for N {
    fn parts(&mut self) -> (&mut dyn Net, Option<Linger<'_>>) {
        (self, None)
    }

    fn clock(&self) -> Option<SharedClock> {
        None
    }
}

/// A network known only by reference, which keeps no connection, the
/// clock of the handles that use it, and the internal trace of the share
/// it is, if that traces (C's `share->admin`).
pub(crate) struct NoSet<'a>(
    pub(crate) &'a mut dyn Net,
    pub(crate) SharedClock,
    pub(crate) Option<Internal>,
);

impl Exits for NoSet<'_> {
    fn parts(&mut self) -> (&mut dyn Net, Option<Linger<'_>>) {
        (&mut *self.0, None)
    }

    fn clock(&self) -> Option<SharedClock> {
        Some(self.1.clone())
    }

    fn internal(&self) -> Option<Internal> {
        self.2.clone()
    }
}

/// A multi's set, as a pool section sees it.
pub(crate) struct Linger<'a> {
    pub(crate) set: &'a mut ShutdownSet,
    /// The multi's total limit (`CURLMOPT_MAX_TOTAL_CONNECTIONS`).
    pub(crate) max_total: Option<NonZeroU32>,
    /// The connections in the multi's own pool, if the section is on
    /// another's (a share's): C caps the set by the multi's pool whichever
    /// pool the connection left.
    pub(crate) multi_pool: Option<u32>,
    /// The multi's room a QUIC connection's goodbye receives in.
    pub(crate) room: &'a mut RecvRoom,
}

/// A network, and the multi's set and receive room behind it.
pub(crate) struct WithSet<'a> {
    pub(crate) net: &'a mut dyn Net,
    pub(crate) set: &'a mut ShutdownSet,
    pub(crate) max_total: Option<NonZeroU32>,
    pub(crate) multi_pool: Option<u32>,
    pub(crate) room: &'a mut RecvRoom,
}

impl Exits for WithSet<'_> {
    fn parts(&mut self) -> (&mut dyn Net, Option<Linger<'_>>) {
        (
            &mut *self.net,
            Some(Linger {
                set: &mut *self.set,
                max_total: self.max_total,
                multi_pool: self.multi_pool,
                room: &mut *self.room,
            }),
        )
    }

    fn clock(&self) -> Option<SharedClock> {
        Some(self.set.clock().clone())
    }
}

/// Discard `conn`, which left a pool holding `pool` connections now
/// (`cpool_discard_conn`): closed at once for an aborted transfer; else
/// shut down once, and kept in the multi's set if that does not finish
/// and `may_linger`, else closed. A share's pool closes what it evicts
/// after the one try (`may_linger` false), but its goodbye's answer, if
/// it awaits one, is awaited first, in the set if there is one.
pub(crate) fn discard(
    conn: Conn,
    aborted: bool,
    may_linger: bool,
    pool: u32,
    exits: &mut dyn Exits,
    now: Instant,
) {
    let clock = exits.clock();
    let alone = exits.internal();
    let (net, mut linger) = exits.parts();
    // Said on the multi's internal trace, or a share's with no multi, as C
    // says it on its internal handle; a connection a multi closes lets one
    // waiting for room look.
    let trace = match linger.as_ref() {
        Some(l) => l.set.internal().cloned(),
        None => alone,
    };
    let in_multi = linger.is_some();
    let mut shutting = Shutting::start(conn, now);
    if aborted {
        shutting.abandon(now, net, trace.as_ref(), in_multi);
    } else {
        let room = linger.as_mut().map(|l| &mut *l.room);
        if shutting.try_once(now, trace.as_ref(), room) != Tried::Done
            && let Some(l) = linger.as_mut()
            && (may_linger || shutting.awaits())
        {
            shutting.once = !may_linger;
            let max = max_shutdowns(l.max_total, l.multi_pool.unwrap_or(pool));
            l.set.add(shutting, max, net);
            return;
        }
        shutting.close(net, clock.as_ref(), trace.as_ref(), in_multi);
    }
    // Closed at once, which a multi notes as its set does
    // (`Curl_cshutdn_terminate`).
    if let Some(l) = linger {
        l.set.conn_changed();
    }
}

#[cfg(test)]
mod tests;
