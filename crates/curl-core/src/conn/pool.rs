//! The connection pool: the owner of every connection, busy or idle, and
//! the only issuer and consumer of leases (`lib/conncache.c`).

use std::net::SocketAddr;
use std::num::NonZeroU32;
use std::time::Duration;

use curl_alloc::{OutOfMemory, TryRc, TryVec as _};

use super::connect::{ConnectError, ConnectMachine, Dialed, Drove, Progress, Setup};
use super::dns::Answer;
use super::io::{Events, Net, Socket, SocketPoll};
use super::{Conn, ConnId, ConnNumber, ConnSlot, Peer, RecvBuf, Route, Transport, Use};
use crate::id::{Arena, ArenaPolicy};
use crate::time::Instant;

/// A transfer's hold on a connection. Only the pool makes one, and only
/// `Pool::release` takes one back; dropping one is a bug, caught in debug
/// builds.
#[must_use]
#[derive(Debug)]
pub(crate) struct ConnLease {
    id: ConnId,
}

impl ConnLease {
    #[cfg_attr(
        not(test),
        expect(dead_code, reason = "the shim's last connection, from step 10")
    )]
    pub(crate) fn id(&self) -> ConnId {
        self.id
    }
}

impl Drop for ConnLease {
    fn drop(&mut self) {
        debug_assert!(
            std::thread::panicking(),
            "the lease on {:?} was dropped, not released",
            self.id
        );
    }
}

/// The lock of a pool that handles share (`CURL_LOCK_DATA_CONNECT`). The
/// pool takes it at the four places C does, each a critical section of
/// its own: a transfer's arrival, the search for a connection to reuse,
/// the addition of a new one, and a connection's return.
pub(crate) trait Lock {
    fn lock(&self);
    fn unlock(&self);
}

/// The lock of a pool no other multi shares: nothing to take.
struct Unshared;

impl Lock for Unshared {
    fn lock(&self) {}
    fn unlock(&self) {}
}

/// A lock held until dropped.
struct Locked<'a>(&'a dyn Lock);

impl<'a> Locked<'a> {
    fn take(lock: &'a dyn Lock) -> Locked<'a> {
        lock.lock();
        Locked(lock)
    }
}

impl Drop for Locked<'_> {
    fn drop(&mut self) {
        self.0.unlock();
    }
}

/// How long the transfer looking for a connection lets one be idle, and
/// live (`CURLOPT_MAXAGE_CONN`, `CURLOPT_MAXLIFETIME_CONN`); none for no
/// limit, as 0 is for either in C.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ReuseRules {
    pub(crate) max_idle: Option<Duration>,
    pub(crate) max_age: Option<Duration>,
    /// No idle connection is to be reused (`reuse_fresh`).
    pub(crate) fresh: bool,
}

/// How the transfer holding a lease finished with the connection
/// (`multi_done`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct Finish {
    /// The transfer stopped before its request was complete, so the
    /// connection's state is unknown.
    pub(crate) premature: bool,
    /// The application forbade the connection's reuse
    /// (`CURLOPT_FORBID_REUSE`).
    pub(crate) forbid_reuse: bool,
}

/// What the pool did with a connection given back (`multi_done_locked`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Released {
    /// Kept for another transfer; the pool was `full`, if it was, and
    /// closed another.
    Idle {
        number: ConnNumber,
        full: Option<Full>,
    },
    /// Kept, then closed at once: the pool was full, and it was the
    /// oldest idle connection.
    Evicted(Full),
    /// Closed, gracefully where the connection has a way to.
    Closed(ConnNumber),
    /// Closed at once: the transfer ended prematurely.
    Terminated(ConnNumber),
}

/// The pool had more connections than it keeps when one went idle, and
/// closed the idle one longest unused, if any was.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Full {
    /// Connections in the pool, busy or idle, before the close.
    pub(crate) conns: u32,
    /// How many it keeps.
    pub(crate) max: u32,
}

/// The limits a new connection is added under
/// (`CURLMOPT_MAX_HOST_CONNECTIONS`, `CURLMOPT_MAX_TOTAL_CONNECTIONS`);
/// none for no limit.
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct AddLimits {
    pub(crate) max_host: Option<NonZeroU32>,
    pub(crate) max_total: Option<NonZeroU32>,
}

/// Why a transfer waits for a connection.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum WaitReason {
    /// As many to its destination as allowed.
    HostLimit,
    /// As many in all as allowed: this many.
    TotalLimit(NonZeroU32),
}

/// A connection for a transfer.
#[derive(Debug)]
pub(crate) enum Acquired {
    /// A new one, to set up.
    New(ConnLease),
    /// An idle one, up already.
    Reused(ConnLease),
    /// None: a new one would pass a limit.
    Wait(WaitReason),
}

/// Something the search for a connection did, for the transfer to trace.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum PoolNote {
    /// A match idle for too long (`cpool_conn_too_old`). One alive too
    /// long is passed over before its health is checked, so says nothing.
    IdleTooLong { idle_ms: u64, max_ms: u64 },
    /// A match not healthy (`url_match_conn`).
    Dead(ConnNumber),
    /// A connection closed, gracefully.
    Closed(ConnNumber),
}

/// What a step of a connection's setup came to.
#[derive(Debug)]
pub(crate) enum Connected {
    /// Still setting up.
    Connecting(Progress),
    /// Up, from `local` to `remote`, found so at `at`.
    Established {
        remote: SocketAddr,
        local: Option<SocketAddr>,
        at: Instant,
    },
    /// Up before this step: a reused connection, from `local` to
    /// `remote`.
    AlreadyUp {
        remote: Option<SocketAddr>,
        local: Option<SocketAddr>,
    },
}

/// Every connection of a multi (or of a share).
pub(crate) struct Pool {
    conns: Arena<ConnSlot>,
    next_number: u64,
    lock: Box<dyn Lock>,
    /// When the search last pruned dead connections (`last_cleanup`).
    last_prune: Option<Instant>,
}

impl Pool {
    pub(crate) fn new() -> Result<Pool, OutOfMemory> {
        Pool::with_lock(curl_alloc::try_box(Unshared)?)
    }

    pub(crate) fn with_lock(lock: Box<dyn Lock>) -> Result<Pool, OutOfMemory> {
        Ok(Pool {
            conns: Arena::new(ArenaPolicy::DOUBLING)?,
            next_number: 0,
            lock,
            last_prune: None,
        })
    }

    /// A transfer joins the multi (`Curl_cpool_xfer_init`): C hands it an
    /// id under the lock; here its id is the multi's, and only the lock is
    /// taken, as an application sharing the pool sees it.
    pub(crate) fn xfer_init(&self) {
        drop(Locked::take(&*self.lock));
    }

    /// A connection for `route`, leased to the caller: an idle one whose
    /// route is equal, healthy and young enough, or a new one within
    /// `limits`, open at once without a network and set up by
    /// `Pool::connect` over one; or none, for want of room. What the
    /// search did is added to `notes`.
    pub(crate) fn acquire(
        &mut self,
        route: Route,
        rules: ReuseRules,
        limits: AddLimits,
        net: &mut dyn Net,
        now: Instant,
        notes: &mut Vec<PoolNote>,
    ) -> Result<Acquired, OutOfMemory> {
        if let Route::Tcp(..) = route
            && !rules.fresh
            && let Some(lease) = self.find(&route, rules, net, now, notes)?
        {
            return Ok(Acquired::Reused(lease));
        }
        let _locked = Locked::take(&*self.lock);
        // A connection without a network is added with no limits
        // (`Curl_cpool_add(data, needle, 0, 0)`).
        if let Route::Tcp(tcp) = &route
            && let Some(reason) = make_room(&mut self.conns, tcp.destination(), limits, net, now)
        {
            return Ok(Acquired::Wait(reason));
        }
        let number = ConnNumber(self.next_number);
        let slot = match route {
            Route::Local => ConnSlot::Open(Conn {
                number,
                route,
                transport: Transport::Local,
                remote: None,
                local: None,
                created: now,
                connected_at: now,
                use_: Use::Leased(NonZeroU32::MIN),
                rx: RecvBuf::default(),
                served: false,
                socks5_authenticated: false,
                seen_version: None,
                close: false,
            }),
            Route::Tcp(tcp) => ConnSlot::Connecting(ConnectMachine::new(number, tcp, now)),
        };
        let id = self.conns.reserve()?.fill(slot);
        self.next_number += 1;
        Ok(Acquired::New(ConnLease { id }))
    }

    /// The search for an idle connection to reuse (`Curl_cpool_find`,
    /// `url_match_conn`), under the lock: a prune of the dead ones at most
    /// once a second, then the first match in the table's order. A match
    /// too old or not healthy is closed and the search goes on.
    fn find(
        &mut self,
        route: &Route,
        rules: ReuseRules,
        net: &mut dyn Net,
        now: Instant,
        notes: &mut Vec<PoolNote>,
    ) -> Result<Option<ConnLease>, OutOfMemory> {
        let lock = &*self.lock;
        let _locked = Locked::take(lock);
        if self
            .last_prune
            .is_none_or(|at| now.since(at) >= Duration::from_secs(1))
        {
            self.last_prune = Some(now);
            prune(&mut self.conns, rules, net, now);
        }
        let mut cursor = None;
        while let Some(id) = self.conns.next_after(cursor) {
            cursor = Some(id);
            let Some(ConnSlot::Open(conn)) = self.conns.get(id) else {
                continue;
            };
            let Use::Idle { since } = conn.use_ else {
                continue;
            };
            if !conn.serves(route) {
                continue;
            }
            let number = conn.number;
            // One that lived too long is passed over for a younger one
            // (`CPOOL_MATCH_TOO_OLD`); one not healthy is reported.
            let verdict = if rules
                .max_age
                .is_some_and(|max| past(now.since(conn.created), max))
            {
                Err(None)
            } else {
                health(conn, since, rules, net, now).map_err(Some)
            };
            match verdict {
                Ok(()) => {
                    let Some(ConnSlot::Open(conn)) = self.conns.get_mut(id) else {
                        unreachable!("just found open");
                    };
                    conn.use_ = Use::Leased(NonZeroU32::MIN);
                    return Ok(Some(ConnLease { id }));
                }
                Err(sick) => {
                    if let Some(why) = sick {
                        if let Some(old) = why {
                            notes.try_push(old)?;
                        }
                        notes.try_push(PoolNote::Dead(number))?;
                    }
                    notes.try_push(PoolNote::Closed(number))?;
                    close(&mut self.conns, id, net);
                }
            }
        }
        Ok(None)
    }

    /// Close every connection no one leases (`Curl_cpool_destroy`).
    pub(crate) fn close_idle(&mut self, net: &mut dyn Net) {
        let mut cursor = None;
        while let Some(id) = self.conns.next_after(cursor) {
            cursor = Some(id);
            if let Some(ConnSlot::Open(conn)) = self.conns.get(id)
                && let Use::Idle { .. } = conn.use_
            {
                close(&mut self.conns, id, net);
            }
        }
    }

    /// Move the leased connection's setup on by one event. A connection
    /// already up says so.
    pub(crate) fn connect(
        &mut self,
        lease: &ConnLease,
        net: &mut dyn Net,
        now: Instant,
        setup: Setup<'_>,
    ) -> Result<Connected, ConnectError> {
        self.conns
            .replace_with(lease.id, |slot| match slot {
                ConnSlot::Connecting(machine) => {
                    let number = machine.number();
                    match machine.drive(net, now, setup) {
                        Ok(Drove::Connecting(m, progress)) => {
                            (ConnSlot::Connecting(m), Ok(Connected::Connecting(progress)))
                        }
                        Ok(Drove::Established(conn)) => {
                            let up = Connected::Established {
                                remote: conn.remote.expect("set up over the network"),
                                local: conn.local,
                                at: conn.connected_at,
                            };
                            (ConnSlot::Open(conn), Ok(up))
                        }
                        Err(e) => (ConnSlot::Failed(number), Err(e)),
                    }
                }
                ConnSlot::Open(conn) => {
                    let up = Connected::AlreadyUp {
                        remote: conn.remote,
                        local: conn.local,
                    };
                    (ConnSlot::Open(conn), Ok(up))
                }
                ConnSlot::Failed(_) => unreachable!("a failed setup is not driven again"),
            })
            .unwrap_or_else(|| panic!("a lease on {:?}, which the pool no longer has", lease.id))
    }

    /// The connection to the proxy a leased setup tunnels through.
    pub(crate) fn dialed(&mut self, lease: &ConnLease) -> &mut Dialed {
        match self.conns.get_mut(lease.id) {
            Some(ConnSlot::Connecting(machine)) => machine.dialed(),
            Some(_) => panic!("{:?} is not setting up", lease.id),
            None => panic!("a lease on {:?}, which the pool no longer has", lease.id),
        }
    }

    /// The leased setup's tunnel is up, and so the connection.
    pub(crate) fn tunneled(&mut self, lease: &ConnLease) -> Connected {
        self.conns
            .replace_with(lease.id, |slot| match slot {
                ConnSlot::Connecting(machine) => {
                    let conn = machine.tunneled();
                    let up = Connected::Established {
                        remote: conn.remote.expect("set up over the network"),
                        local: conn.local,
                        at: conn.connected_at,
                    };
                    (ConnSlot::Open(conn), up)
                }
                ConnSlot::Open(_) | ConnSlot::Failed(_) => {
                    panic!("{:?} is not setting up", lease.id)
                }
            })
            .unwrap_or_else(|| panic!("a lease on {:?}, which the pool no longer has", lease.id))
    }

    /// Start the leased setup over, as its proxy closed the connection;
    /// false if it was started over too often.
    pub(crate) fn redial(&mut self, lease: &ConnLease, net: &mut dyn Net) -> bool {
        match self.conns.get_mut(lease.id) {
            Some(ConnSlot::Connecting(machine)) => machine.redial(net),
            Some(_) => panic!("{:?} is not setting up", lease.id),
            None => panic!("a lease on {:?}, which the pool no longer has", lease.id),
        }
    }

    /// The connection a lease holds, once up.
    pub(crate) fn get(&mut self, lease: &ConnLease) -> &mut Conn {
        match self.conns.get_mut(lease.id) {
            Some(ConnSlot::Open(conn)) => conn,
            Some(_) => panic!("{:?} is not up", lease.id),
            None => panic!("a lease on {:?}, which the pool no longer has", lease.id),
        }
    }

    /// The connection `id` names, if it is still in the pool and up.
    #[cfg_attr(
        not(test),
        expect(dead_code, reason = "the shim's last connection, from step 10")
    )]
    pub(crate) fn get_conn(&self, id: ConnId) -> Option<&Conn> {
        match self.conns.get(id)? {
            ConnSlot::Open(conn) => Some(conn),
            ConnSlot::Connecting(_) | ConnSlot::Failed(_) => None,
        }
    }

    /// What the name of a connection being set up resolved to, once it
    /// has.
    pub(crate) fn answer(&self, lease: &ConnLease) -> Option<TryRc<Answer>> {
        match self.conns.get(lease.id) {
            Some(ConnSlot::Connecting(m)) => m.answer().cloned(),
            Some(ConnSlot::Open(_) | ConnSlot::Failed(_)) => None,
            None => panic!("a lease on {:?}, which the pool no longer has", lease.id),
        }
    }

    /// The sockets of the connection a lease holds: its attempts' while
    /// it is set up, none without a network.
    pub(crate) fn sockets(&self, lease: &ConnLease) -> impl Iterator<Item = &dyn Socket> {
        let (setup, open) = match self.conns.get(lease.id) {
            Some(ConnSlot::Connecting(m)) => (Some(m), None),
            Some(ConnSlot::Open(Conn {
                transport: Transport::Tcp(socket),
                ..
            })) => (None, Some(&**socket)),
            Some(ConnSlot::Open(_) | ConnSlot::Failed(_)) => (None, None),
            None => panic!("a lease on {:?}, which the pool no longer has", lease.id),
        };
        setup
            .into_iter()
            .flat_map(ConnectMachine::sockets)
            .chain(open)
    }

    /// Take a lease back and decide the connection's fate as
    /// `multi_done_locked` does: kept idle if its protocol allows reuse
    /// and the transfer finished with it, else closed. A connection kept
    /// may leave the pool over its limit (`cpool_conn_now_idle`).
    pub(crate) fn release(
        &mut self,
        lease: ConnLease,
        finish: Finish,
        limit: Limit,
        net: &mut dyn Net,
        now: Instant,
    ) -> Released {
        let id = lease.id;
        std::mem::forget(lease);
        let _locked = Locked::take(&*self.lock);
        if let Some(ConnSlot::Open(conn)) = self.conns.get_mut(id)
            && let Route::Tcp(tcp) = &conn.route
            && tcp.origin.scheme().reuse
            && !finish.premature
            && !finish.forbid_reuse
            && !conn.close
        {
            assert_eq!(conn.use_, Use::Leased(NonZeroU32::MIN), "one lease");
            conn.use_ = Use::Idle { since: now };
            conn.served = true;
            let number = conn.number;
            return match over_limit(&mut self.conns, limit, net, now) {
                Some((full, closed)) if closed == Some(id) => Released::Evicted(full),
                full => Released::Idle {
                    number,
                    full: full.map(|(full, _)| full),
                },
            };
        }
        let slot = self
            .conns
            .remove(id)
            .unwrap_or_else(|| panic!("a lease on {id:?}, which the pool no longer has"));
        let number = match slot {
            ConnSlot::Connecting(m) => {
                let number = m.number();
                m.close(net);
                number
            }
            ConnSlot::Open(conn) => {
                close_transport(conn.transport, net);
                conn.number
            }
            ConnSlot::Failed(number) => number,
        };
        if finish.premature {
            Released::Terminated(number)
        } else {
            Released::Closed(number)
        }
    }

    /// Connections in the pool, busy or idle.
    #[cfg(test)]
    pub(crate) fn len(&self) -> u32 {
        self.conns.len()
    }

    /// Connections leased: every one not idle.
    #[cfg(debug_assertions)]
    pub(crate) fn leased(&self) -> usize {
        let mut leased = 0;
        let mut cursor = None;
        while let Some(id) = self.conns.next_after(cursor) {
            cursor = Some(id);
            leased += usize::from(!matches!(
                self.conns.get(id),
                Some(ConnSlot::Open(Conn {
                    use_: Use::Idle { .. },
                    ..
                }))
            ));
        }
        leased
    }
}

/// How many connections a pool keeps once one goes idle
/// (`CURLMOPT_MAXCONNECTS`); with none set, a guess from the transfers.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Limit {
    pub(crate) max: Option<NonZeroU32>,
    /// The transfers in the multi (`Curl_multi_xfers_attached`).
    pub(crate) attached: u32,
}

/// With more connections than `limit` keeps, close the idle one longest
/// unused (`cpool_conn_now_idle`, `cpool_get_oldest_idle`). Without a
/// limit set, the pool keeps twice the transfers, and closes only a
/// connection idle for a second.
fn over_limit(
    conns: &mut Arena<ConnSlot>,
    limit: Limit,
    net: &mut dyn Net,
    now: Instant,
) -> Option<(Full, Option<ConnId>)> {
    let (max, min_idle_ms) = match limit.max {
        Some(max) => (max.get(), 0),
        None => (limit.attached.saturating_mul(2), 1000),
    };
    if max == 0 || max == u32::MAX {
        return None;
    }
    let mut count = 0;
    let mut oldest = None;
    let mut cursor = None;
    while let Some(id) = conns.next_after(cursor) {
        cursor = Some(id);
        match conns.get(id) {
            Some(ConnSlot::Failed(_)) | None => continue,
            Some(ConnSlot::Open(Conn {
                use_: Use::Idle { since },
                ..
            })) => {
                // In C's milliseconds: of two as old, the first.
                let idle_ms = now.since(*since).as_millis();
                if idle_ms >= min_idle_ms && oldest.is_none_or(|(_, ms)| idle_ms > ms) {
                    oldest = Some((id, idle_ms));
                }
            }
            Some(ConnSlot::Open(_) | ConnSlot::Connecting(_)) => {}
        }
        count += 1;
    }
    if count <= max {
        return None;
    }
    let closed = oldest.map(|(id, _)| id);
    if let Some(id) = closed {
        close(conns, id, net);
    }
    Some((Full { conns: count, max }, closed))
}

/// Make room for a connection to `to` within `limits`, closing idle ones
/// longest unused, first among those to the same destination
/// (`cpool_check_limits`); why there is none, if there is not. The
/// closes trace nowhere, as C's go to its internal handle.
fn make_room(
    conns: &mut Arena<ConnSlot>,
    to: &Peer,
    limits: AddLimits,
    net: &mut dyn Net,
    now: Instant,
) -> Option<WaitReason> {
    let to_host = |slot: &ConnSlot| slot.destination().is_some_and(|d| d.same_bundle(to));
    if let Some(max) = limits.max_host {
        let live = count(conns, to_host);
        for _ in max.get()..=live {
            let Some(id) = oldest_idle(conns, to_host, now) else {
                break;
            };
            close(conns, id, net);
        }
        if count(conns, to_host) >= max.get() {
            return Some(WaitReason::HostLimit);
        }
    }
    if let Some(max) = limits.max_total {
        let any = |_: &ConnSlot| true;
        let live = count(conns, any);
        for _ in max.get()..=live {
            let Some(id) = oldest_idle(conns, any, now) else {
                break;
            };
            close(conns, id, net);
        }
        if count(conns, any) >= max.get() {
            return Some(WaitReason::TotalLimit(max));
        }
    }
    None
}

/// The connections `which` picks, busy, idle or being set up; a failed
/// setup holds nothing.
fn count(conns: &Arena<ConnSlot>, which: impl Fn(&ConnSlot) -> bool) -> u32 {
    let mut n = 0;
    let mut cursor = None;
    while let Some(id) = conns.next_after(cursor) {
        cursor = Some(id);
        if let Some(slot) = conns.get(id)
            && !matches!(slot, ConnSlot::Failed(_))
            && which(slot)
        {
            n += 1;
        }
    }
    n
}

/// The idle connection `which` picks that has been unused longest; of
/// two as old in C's milliseconds, the first (`cpool_get_oldest_idle`,
/// `cpool_bundle_get_oldest_idle`).
fn oldest_idle(
    conns: &Arena<ConnSlot>,
    which: impl Fn(&ConnSlot) -> bool,
    now: Instant,
) -> Option<ConnId> {
    let mut oldest: Option<(ConnId, u128)> = None;
    let mut cursor = None;
    while let Some(id) = conns.next_after(cursor) {
        cursor = Some(id);
        if let Some(
            slot @ ConnSlot::Open(Conn {
                use_: Use::Idle { since },
                ..
            }),
        ) = conns.get(id)
            && which(slot)
        {
            let idle_ms = now.since(*since).as_millis();
            if oldest.is_none_or(|(_, ms)| idle_ms > ms) {
                oldest = Some((id, idle_ms));
            }
        }
    }
    oldest.map(|(id, _)| id)
}

/// Close the idle connections that are not healthy, saying nothing: C's
/// prune traces to its internal handle (`cpool_prune_dead`).
fn prune(conns: &mut Arena<ConnSlot>, rules: ReuseRules, net: &mut dyn Net, now: Instant) {
    let mut cursor = None;
    while let Some(id) = conns.next_after(cursor) {
        cursor = Some(id);
        if let Some(ConnSlot::Open(conn)) = conns.get(id)
            && let Use::Idle { since } = conn.use_
            && health(conn, since, rules, net, now).is_err()
        {
            close(conns, id, net);
        }
    }
}

/// Close the connection `id` names, which no one leases.
fn close(conns: &mut Arena<ConnSlot>, id: ConnId, net: &mut dyn Net) {
    match conns.remove(id) {
        Some(ConnSlot::Open(conn)) => {
            assert!(matches!(conn.use_, Use::Idle { .. }), "{id:?} is leased");
            close_transport(conn.transport, net);
        }
        other => unreachable!("closing {id:?}, which is {other:?}"),
    }
}

/// Whether an idle connection may be reused
/// (`Curl_cpool_conn_seems_healthy`): not idle or alive too long, and with
/// nothing to read, as an idle HTTP/1 connection must not have (RFC 9112,
/// section 9.2) and a closed one has.
fn health(
    conn: &Conn,
    idle_since: Instant,
    rules: ReuseRules,
    net: &mut dyn Net,
    now: Instant,
) -> Result<(), Option<PoolNote>> {
    let idle = now.since(idle_since);
    if let Some(max) = rules.max_idle
        && past(idle, max)
    {
        return Err(Some(PoolNote::IdleTooLong {
            idle_ms: whole_ms(idle),
            max_ms: whole_ms(max),
        }));
    }
    // Only the prune meets one alive too long here, and says nothing.
    if rules
        .max_age
        .is_some_and(|max| past(now.since(conn.created), max))
    {
        return Err(None);
    }
    let Transport::Tcp(socket) = &conn.transport else {
        return Ok(());
    };
    let mut watch = [SocketPoll::new(&**socket, Events::IN)];
    match net.poll(&mut watch, &mut [], Duration::ZERO) {
        Ok(_) if watch[0].revents().is_empty() => Ok(()),
        Ok(_) | Err(_) => Err(None),
    }
}

/// Whether `elapsed` is past the limit `max`, counted in whole
/// milliseconds as C counts them (`age_ms > conn_max_idle_ms`).
fn past(elapsed: Duration, max: Duration) -> bool {
    whole_ms(elapsed) > whole_ms(max)
}

fn whole_ms(d: Duration) -> u64 {
    u64::try_from(d.as_millis()).unwrap_or(u64::MAX)
}

fn close_transport(transport: Transport, net: &mut dyn Net) {
    match transport {
        Transport::Local => {}
        Transport::Tcp(socket) => net.close(socket),
    }
}

#[cfg(test)]
mod tests;
