//! The connection pool: the owner of every connection, busy or idle, and
//! the only issuer and consumer of leases (`lib/conncache.c`).

use std::net::SocketAddr;
use std::num::NonZeroU32;
use std::time::Duration;

use curl_alloc::{OutOfMemory, TryVec as _};

use super::connect::{ConnectError, ConnectMachine, Drove, Progress};
use super::io::{Events, Net, Socket, SocketPoll};
use super::{Conn, ConnId, ConnNumber, ConnSlot, Route, Transport, Use};
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
/// limit.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ReuseRules {
    pub(crate) max_idle: Option<Duration>,
    pub(crate) max_age: Option<Duration>,
}

/// How the transfer holding a lease finished with the connection
/// (`multi_done`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct Finish {
    /// The transfer stopped before its request was complete, so the
    /// connection's state is unknown.
    pub(crate) premature: bool,
}

/// What the pool did with a connection given back (`multi_done_locked`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Released {
    /// Kept for another transfer.
    Idle(ConnNumber),
    /// Closed, gracefully where the connection has a way to.
    Closed(ConnNumber),
    /// Closed at once: the transfer ended prematurely.
    Terminated(ConnNumber),
}

/// A connection for a transfer.
#[derive(Debug)]
pub(crate) enum Acquired {
    /// A new one, to set up.
    New(ConnLease),
    /// An idle one, up already.
    Reused(ConnLease),
}

/// Something the search for a connection did, for the transfer to trace.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum PoolNote {
    /// A match idle for too long (`cpool_conn_too_old`).
    IdleTooLong { idle_ms: u64, max_ms: u64 },
    /// A match that lived too long, judged by its health check.
    LivedTooLong { age_ms: u64, max_ms: u64 },
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
    /// Up before this step: a reused connection.
    AlreadyUp,
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
    /// route is equal, healthy and young enough, or a new one, open at
    /// once without a network and set up by `Pool::connect` over one.
    /// What the search did is added to `notes`.
    pub(crate) fn acquire(
        &mut self,
        route: Route,
        rules: ReuseRules,
        net: &mut dyn Net,
        now: Instant,
        notes: &mut Vec<PoolNote>,
    ) -> Result<Acquired, OutOfMemory> {
        if let Route::Tcp(..) = route
            && let Some(lease) = self.find(&route, rules, net, now, notes)?
        {
            return Ok(Acquired::Reused(lease));
        }
        let _locked = Locked::take(&*self.lock);
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
            }),
            Route::Tcp(scheme, dest) => {
                ConnSlot::Connecting(ConnectMachine::new(number, scheme, dest, now))
            }
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
            if conn.route != *route {
                continue;
            }
            let number = conn.number;
            // One that lived too long is passed over for a younger one
            // (`CPOOL_MATCH_TOO_OLD`); one not healthy is reported.
            let verdict = if rules
                .max_age
                .is_some_and(|max| now.since(conn.created) > max)
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
    ) -> Result<Connected, ConnectError> {
        self.conns
            .replace_with(lease.id, |slot| match slot {
                ConnSlot::Connecting(machine) => {
                    let number = machine.number();
                    match machine.drive(net, now) {
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
                open @ ConnSlot::Open(_) => (open, Ok(Connected::AlreadyUp)),
                ConnSlot::Failed(_) => unreachable!("a failed setup is not driven again"),
            })
            .unwrap_or_else(|| panic!("a lease on {:?}, which the pool no longer has", lease.id))
    }

    /// The connection a lease holds, once up.
    #[cfg_attr(
        not(test),
        expect(dead_code, reason = "protocols reach their connection, from step 12")
    )]
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

    /// Every socket the pool's connections wait on, and for what.
    pub(crate) fn sockets<'a>(&'a self, mut f: impl FnMut(&'a dyn Socket, Events)) {
        let mut cursor = None;
        while let Some(id) = self.conns.next_after(cursor) {
            cursor = Some(id);
            if let Some(ConnSlot::Connecting(m)) = self.conns.get(id)
                && let Some((socket, events)) = m.socket()
            {
                f(socket, events);
            }
        }
    }

    /// Take a lease back and decide the connection's fate as
    /// `multi_done_locked` does: kept idle if its protocol allows reuse
    /// and the transfer finished with it, else closed.
    pub(crate) fn release(
        &mut self,
        lease: ConnLease,
        finish: Finish,
        net: &mut dyn Net,
        now: Instant,
    ) -> Released {
        let id = lease.id;
        std::mem::forget(lease);
        let _locked = Locked::take(&*self.lock);
        if let Some(ConnSlot::Open(conn)) = self.conns.get_mut(id)
            && let Route::Tcp(scheme, _) = conn.route
            && scheme.reuse
            && !finish.premature
        {
            assert_eq!(conn.use_, Use::Leased(NonZeroU32::MIN), "one lease");
            conn.use_ = Use::Idle { since: now };
            return Released::Idle(conn.number);
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
        && idle > max
    {
        return Err(Some(PoolNote::IdleTooLong {
            idle_ms: whole_ms(idle),
            max_ms: whole_ms(max),
        }));
    }
    let age = now.since(conn.created);
    if let Some(max) = rules.max_age
        && age > max
    {
        return Err(Some(PoolNote::LivedTooLong {
            age_ms: whole_ms(age),
            max_ms: whole_ms(max),
        }));
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
