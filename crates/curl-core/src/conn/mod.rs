//! Connections: what a transfer talks over, owned by the pool and leased to
//! transfers.
//!
//! A networkless connection is what `file:` leases, as C attaches a
//! connection to every transfer. A TCP one is set up by a
//! `ConnectMachine`, in the slot it keeps once established. `io` is the
//! engine's way to the network.

mod connect;
pub mod io;
mod pool;

pub(crate) use connect::{ConnectError, Progress};
pub(crate) use pool::{ConnLease, Connected, Finish, Pool, Released};

use std::fmt;
use std::net::SocketAddr;

use curl_alloc::{OutOfMemory, TryVec as _};

use self::connect::ConnectMachine;
use self::io::Socket;
use crate::id::Key;
use crate::time::Instant;

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
    /// Being set up.
    Connecting(ConnectMachine),
    Open(Conn),
    /// Its setup failed; it holds nothing open, and goes when its lease
    /// is given back.
    Failed(ConnNumber),
}

/// What a transfer needs of a connection, decided once per leg. Two
/// transfers may share a connection only if their routes allow it.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub(crate) enum Route {
    /// No network: the protocol does its own I/O (C's
    /// `PROTOPT_NONETWORK`).
    Local,
    Tcp(Destination),
}

/// Where a connection goes: the host as the URL holds it, and the port.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub(crate) struct Destination {
    host: Vec<u8>,
    port: u16,
}

impl Destination {
    pub(crate) fn new(host: &[u8], port: u16) -> Result<Destination, OutOfMemory> {
        let mut owned = Vec::new();
        owned.try_extend_from_slice(host)?;
        Ok(Destination { host: owned, port })
    }
}

/// What a connection's bytes travel over.
#[derive(Debug)]
pub(crate) enum Transport {
    Local,
    Tcp(Box<dyn Socket>),
}

/// An established connection.
#[derive(Debug)]
pub(crate) struct Conn {
    number: ConnNumber,
    transport: Transport,
    /// The address connected to, and from; none without a network.
    remote: Option<SocketAddr>,
    local: Option<SocketAddr>,
    /// When it was found connected (TIMER_CONNECT's `connected_at`).
    connected_at: Instant,
}
