//! Connections: what a transfer talks over, owned by the pool and leased to
//! transfers.
//!
//! Only networkless connections exist yet, which `file:` leases as C
//! attaches a connection to every transfer; the multi uses them from
//! milestone 1 step 5b (MILESTONES.md). `io` is the engine's way to the
//! network.

pub mod io;
mod pool;

pub(crate) use pool::{ConnLease, Finish, Pool};

use std::fmt;

use crate::id::Key;

/// A connection's number in its pool, counting from 0 in the order the
/// pool made them: the `#N` of "Connection #N" (C's `connection_id`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ConnNumber(u64);

impl fmt::Display for ConnNumber {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "#{}", self.0)
    }
}

/// A connection's place in the pool; stale once the connection is gone.
pub(crate) type ConnId = Key<ConnSlot>;

/// A connection in the pool.
#[derive(Debug)]
pub(crate) enum ConnSlot {
    #[cfg_attr(
        not(test),
        expect(dead_code, reason = "read through Pool::get, from step 8")
    )]
    Open(Conn),
}

/// What a transfer needs of a connection, decided once per leg. Two
/// transfers may share a connection only if their routes allow it.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub(crate) struct Route {
    transport: TransportKind,
}

impl Route {
    /// A route with no network: the protocol does its own I/O (C's
    /// `PROTOPT_NONETWORK`).
    pub(crate) const LOCAL: Route = Route {
        transport: TransportKind::Local,
    };
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
enum TransportKind {
    Local,
}

/// An established connection.
#[derive(Debug)]
pub(crate) struct Conn {
    #[cfg_attr(
        not(test),
        expect(dead_code, reason = "the trace names connections, from step 9")
    )]
    number: ConnNumber,
}

impl Conn {
    #[cfg_attr(
        not(test),
        expect(dead_code, reason = "the trace names connections, from step 9")
    )]
    pub(crate) fn number(&self) -> ConnNumber {
        self.number
    }
}
