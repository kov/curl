//! The connection pool: the owner of every connection, busy or idle, and
//! the only issuer and consumer of leases (`lib/conncache.c`).

use curl_alloc::OutOfMemory;

use super::{Conn, ConnId, ConnNumber, ConnSlot, Route};
use crate::id::{Arena, ArenaPolicy};

/// A transfer's hold on a connection. Only the pool makes one, and only
/// `Pool::release` takes one back; dropping one is a bug, caught in debug
/// builds.
#[must_use]
#[derive(Debug)]
pub(crate) struct ConnLease {
    id: ConnId,
}

impl ConnLease {
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
    /// Closed, gracefully where the connection has a way to.
    Closed,
    /// Closed at once: the transfer ended prematurely.
    Terminated,
}

/// Every connection of a multi (or of a share).
pub(crate) struct Pool {
    conns: Arena<ConnSlot>,
    next_number: u64,
}

impl Pool {
    pub(crate) fn new() -> Result<Pool, OutOfMemory> {
        Ok(Pool {
            conns: Arena::new(ArenaPolicy::new(16, 0).expect("a valid policy"))?,
            next_number: 0,
        })
    }

    /// A connection for `route`, leased to the caller. A networkless
    /// route always gets a new connection, which C also adds to its pool.
    pub(crate) fn acquire(&mut self, route: &Route) -> Result<ConnLease, OutOfMemory> {
        let vacancy = self.conns.reserve()?;
        let number = ConnNumber(self.next_number);
        self.next_number += 1;
        let id = vacancy.fill(ConnSlot::Open(Conn {
            route: route.clone(),
            number,
        }));
        Ok(ConnLease { id })
    }

    /// The connection a lease holds.
    pub(crate) fn get(&mut self, lease: &ConnLease) -> &mut Conn {
        match self.conns.get_mut(lease.id) {
            Some(ConnSlot::Open(conn)) => conn,
            None => panic!("a lease on {:?}, which the pool no longer has", lease.id),
        }
    }

    /// The connection `id` names, if it is still in the pool.
    pub(crate) fn get_conn(&self, id: ConnId) -> Option<&Conn> {
        match self.conns.get(id)? {
            ConnSlot::Open(conn) => Some(conn),
        }
    }

    /// Take a lease back and decide the connection's fate as
    /// `multi_done_locked` does.
    pub(crate) fn release(&mut self, lease: ConnLease, finish: Finish) -> Released {
        let id = lease.id;
        std::mem::forget(lease);
        // No route allows sharing or reuse yet: a connection has one lease
        // and closes with it. Sharing, keeping a connection idle for the
        // next transfer, and the reasons C closes one anyway, come with the
        // network.
        assert!(
            self.conns.remove(id).is_some(),
            "a lease on {id:?}, which the pool no longer has"
        );
        if finish.premature {
            Released::Terminated
        } else {
            Released::Closed
        }
    }

    /// Connections in the pool, busy or idle.
    pub(crate) fn len(&self) -> u32 {
        self.conns.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn local_connections_are_numbered_and_closed_when_released() {
        let mut pool = Pool::new().unwrap();
        let a = pool.acquire(&Route::LOCAL).unwrap();
        let b = pool.acquire(&Route::LOCAL).unwrap();
        assert_ne!(a.id(), b.id(), "a local connection is never shared");
        assert_eq!(pool.get(&a).number().to_string(), "#0");
        assert_eq!(pool.get(&b).number().to_string(), "#1");
        assert_eq!(pool.len(), 2);
        let a_id = a.id();
        assert_eq!(pool.release(a, Finish::default()), Released::Closed);
        assert!(pool.get_conn(a_id).is_none());
        let premature = Finish { premature: true };
        assert_eq!(pool.release(b, premature), Released::Terminated);
        assert_eq!(pool.len(), 0);
        // Numbers are never reused.
        let c = pool.acquire(&Route::LOCAL).unwrap();
        assert_eq!(pool.get(&c).number().to_string(), "#2");
        assert_eq!(pool.release(c, Finish::default()), Released::Closed);
    }

    #[test]
    #[cfg(debug_assertions)]
    #[should_panic = "dropped, not released"]
    fn a_dropped_lease_is_caught() {
        let mut pool = Pool::new().unwrap();
        drop(pool.acquire(&Route::LOCAL).unwrap());
    }
}
