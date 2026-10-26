//! Connections shutting down (`lib/cshutdn.c`): those whose layers say
//! goodbye to the peer over more than one pass, as TLS's close_notify may.
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

use super::io::{Events, Net, Socket, SocketKey};
use super::layer::Handshake;
use super::{Conn, Peer, Route, Transport};
use crate::components::Component;
use crate::time::Instant;
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
}

impl ConnSettings {
    /// What a transfer's connections keep: the defaults, as no option
    /// changes them.
    pub(crate) const DEFAULT: ConnSettings = ConnSettings { shutdown_ms: 2000 };
}

/// A connection in a closing set, and how far its shutdown got.
#[derive(Debug)]
pub(crate) struct Shutting {
    conn: Conn,
    /// Its layers already shut down, counted from the top: the shutdown
    /// goes down the stack, a layer's starting once the one above is done
    /// (`Curl_cshutdn_try_once_idx`).
    shut: usize,
    /// When the shutdown started, in whole milliseconds after the
    /// connection was created (C's `shutdown.start_ms`).
    started_ms: u64,
    /// It was tried once at least: its start was said.
    tried: bool,
    /// A try finished it, its layers done, failed or out of time
    /// (`bits.shutdown_filters`): its close is no forced one.
    finished: bool,
}

/// What one try of a shutdown came to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Tried {
    /// Finished, or failed, or out of time: the connection is to close.
    Done,
    /// Its layers wait for the socket.
    Waiting,
}

impl Shutting {
    /// The shutdown of `conn` starts at `now` (`Curl_cshutdn_start_timer`).
    pub(crate) fn start(conn: Conn, now: Instant) -> Shutting {
        let started_ms = whole_ms(now.since(conn.created));
        Shutting {
            conn,
            shut: 0,
            started_ms,
            tried: false,
            finished: false,
        }
    }

    /// Milliseconds left at `now` of the shutdown's time, -1 for none
    /// (`Curl_cshutdn_timeleft_ms`, whose 0 means no limit).
    fn left_ms(&self, now: Instant) -> i64 {
        let limit = i64::from(self.conn.settings.shutdown_ms);
        let spent = whole_ms(now.since(self.conn.created)).saturating_sub(self.started_ms);
        match limit.saturating_sub(i64::try_from(spent).unwrap_or(i64::MAX)) {
            0 => -1,
            left => left,
        }
    }

    /// Move the shutdown on once at `now` (`cshutdn_run_once`): out of
    /// time, it is done; else each layer from the top that is not shut
    /// down yet, then the socket's own, which reads and drops up to 1 KB
    /// so the kernel answers the peer's last bytes with no reset
    /// (`cf_socket_shutdown`). A layer that fails ends it. Said on
    /// `trace` as C's internal handle says it (`Curl_cshutdn_try_once`).
    pub(crate) fn try_once(&mut self, now: Instant, trace: Option<&Internal>) -> Tried {
        let tried = self.run_once(now, trace);
        if tried == Tried::Done {
            self.finished = true;
        }
        if let Some(t) = trace {
            let done = u8::from(tried == Tried::Done);
            t.of(
                Component::Multi,
                format_args!("[SHUTDOWN] shutdown, done={done}"),
            );
        }
        tried
    }

    fn run_once(&mut self, now: Instant, trace: Option<&Internal>) -> Tried {
        let mut cx = InternalCx { now, trace };
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
        // HTTP/2 says goodbye first (`cf_h2_shutdown`).
        if let Some(mut h2) = self.conn.take_h2() {
            h2.goodbye(&mut cx, &mut self.conn);
            self.conn.put_h2(h2);
        }
        let Transport::Tcp(stream) = &mut self.conn.transport else {
            return Tried::Done;
        };
        match stream.shutdown(&mut cx, &mut self.shut) {
            Ok(Handshake::Waiting) => Tried::Waiting,
            Ok(Handshake::Done) | Err(_) => Tried::Done,
        }
    }

    /// Close it at once, whatever its layers were doing
    /// (`Curl_cshutdn_terminate`): only the socket closes, nothing more
    /// is read from it. Said on `trace`, and, `in_multi`, that a transfer
    /// waiting for room may find some.
    pub(crate) fn close(self, net: &mut dyn Net, trace: Option<&Internal>, in_multi: bool) {
        terminate(self.conn, self.finished, net, trace, in_multi);
    }

    /// What it waits on while it shuts down: what its layers not shut down
    /// yet say, from the top (`Curl_conn_adjust_pollset` on a chain in
    /// shutdown, its connected socket adding nothing).
    fn pollset(&self) -> Option<(&dyn Socket, Events)> {
        let Transport::Tcp(stream) = &self.conn.transport else {
            return None;
        };
        let events = stream.shutdown_pollset(self.shut);
        (!events.is_empty()).then(|| (stream.socket(), events))
    }

    /// The peer it goes to, for the limits on connections to one host.
    fn destination(&self) -> Option<&Peer> {
        match &self.conn.route {
            Route::Tcp(tcp) => Some(tcp.destination()),
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
    match conn.transport {
        Transport::Local => {}
        Transport::Tcp(stream) => {
            let socket = stream.into_socket();
            if let Some(t) = trace {
                let fd = socket.key().get();
                t.of(
                    Component::Multi,
                    format_args!("Curl_multi_will_close fd={fd}"),
                );
            }
            net.close(socket);
        }
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
#[derive(Debug, Default)]
pub(crate) struct ShutdownSet {
    conns: Vec<Entry>,
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
    /// A connection of it closed: a transfer waiting for room may find
    /// some (`Curl_multi_connchanged`).
    changed: bool,
    /// The multi's internal trace, if it has one.
    trace: Option<Internal>,
}

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
    /// here (`Curl_cshutdn_add`). With no room for it, it is closed.
    pub(crate) fn add(&mut self, shutting: Shutting, max: usize, net: &mut dyn Net) {
        if max <= self.conns.len() {
            self.say(format_args!(
                "[SHUTDOWN] discarding oldest shutdown connection due to shutdown limit of {max}"
            ));
            self.close_oldest(None, 1, net);
        }
        let n = shutting.conn.number.get();
        if self.conns.try_reserve(1).is_err() {
            self.say(format_args!("[SHUTDOWN] adding failed, discarding #{n}"));
            shutting.close(net, self.trace.as_ref(), true);
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

    /// Close up to `n` of the oldest, of those to `to` if given
    /// (`Curl_cshutdn_close_oldest`); how many were.
    pub(crate) fn close_oldest(&mut self, to: Option<&Peer>, n: u32, net: &mut dyn Net) -> u32 {
        let mut closed = 0;
        let mut i = 0;
        while closed < n && i < self.conns.len() {
            let goes = to.is_none_or(|to| {
                self.conns[i]
                    .shutting
                    .destination()
                    .is_some_and(|d| d.same_bundle(to))
            });
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
    /// others.
    pub(crate) fn perform(&mut self, net: &mut dyn Net, now: Instant) {
        if self.conns.is_empty() {
            return;
        }
        let n = self.conns.len();
        self.say(format_args!("[SHUTDOWN] perform on {n} connections"));
        let mut next_ms: i64 = 0;
        let mut i = 0;
        while i < self.conns.len() {
            let trace = self.trace.as_ref();
            if self.conns[i].shutting.try_once(now, trace) == Tried::Done {
                let entry = self.conns.remove(i);
                self.closed(entry, net);
                continue;
            }
            let ms = self.conns[i].shutting.left_ms(now);
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

    /// Close `entry`, which has left the set.
    fn closed(&mut self, entry: Entry, net: &mut dyn Net) {
        entry.shutting.close(net, self.trace.as_ref(), true);
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

    /// A connection closed since last asked.
    pub(crate) fn take_changed(&mut self) -> bool {
        std::mem::take(&mut self.changed)
    }
}

/// Where the connections leaving a pool go: closed through a network, and,
/// for one that shuts down slowly, kept in a multi's set if there is one.
/// A network alone keeps none: what does not finish in one try is closed,
/// as C does with no multi (a share's cleanup).
pub(crate) trait Exits {
    fn parts(&mut self) -> (&mut dyn Net, Option<Linger<'_>>);
}

impl<N: Net> Exits for N {
    fn parts(&mut self) -> (&mut dyn Net, Option<Linger<'_>>) {
        (self, None)
    }
}

/// A network known only by reference, which keeps no connection.
pub(crate) struct NoSet<'a>(pub(crate) &'a mut dyn Net);

impl Exits for NoSet<'_> {
    fn parts(&mut self) -> (&mut dyn Net, Option<Linger<'_>>) {
        (&mut *self.0, None)
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
}

/// A network, and the multi's set behind it.
pub(crate) struct WithSet<'a> {
    pub(crate) net: &'a mut dyn Net,
    pub(crate) set: &'a mut ShutdownSet,
    pub(crate) max_total: Option<NonZeroU32>,
    pub(crate) multi_pool: Option<u32>,
}

impl Exits for WithSet<'_> {
    fn parts(&mut self) -> (&mut dyn Net, Option<Linger<'_>>) {
        (
            &mut *self.net,
            Some(Linger {
                set: &mut *self.set,
                max_total: self.max_total,
                multi_pool: self.multi_pool,
            }),
        )
    }
}

/// Discard `conn`, which left a pool holding `pool` connections now
/// (`cpool_discard_conn`): closed at once for an aborted transfer; else
/// shut down once, and kept in the multi's set if that does not finish
/// and `may_linger` (a share's pool closes what it evicts), else closed.
pub(crate) fn discard(
    conn: Conn,
    aborted: bool,
    may_linger: bool,
    pool: u32,
    exits: &mut dyn Exits,
    now: Instant,
) {
    let (net, linger) = exits.parts();
    // Said on the multi's internal trace, as C says it on its internal
    // handle; a connection a multi closes lets one waiting for room look.
    let trace = linger.as_ref().and_then(|l| l.set.internal().cloned());
    let in_multi = linger.is_some();
    let mut shutting = Shutting::start(conn, now);
    if aborted {
        shutting.close(net, trace.as_ref(), in_multi);
        return;
    }
    if shutting.try_once(now, trace.as_ref()) == Tried::Done {
        shutting.close(net, trace.as_ref(), in_multi);
        return;
    }
    match linger.filter(|_| may_linger) {
        Some(l) => {
            let max = max_shutdowns(l.max_total, l.multi_pool.unwrap_or(pool));
            l.set.add(shutting, max, net);
        }
        None => shutting.close(net, trace.as_ref(), in_multi),
    }
}

fn whole_ms(d: Duration) -> u64 {
    u64::try_from(d.as_millis()).unwrap_or(u64::MAX)
}

#[cfg(test)]
mod tests;
