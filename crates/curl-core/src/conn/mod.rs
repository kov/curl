//! Connections: what a transfer talks over, owned by the pool and leased to
//! transfers.
//!
//! A networkless connection is what `file:` leases, as C attaches a
//! connection to every transfer. A TCP one is set up by a
//! `ConnectMachine`, in the slot it keeps once established. `io` is the
//! engine's way to the network.

mod buf;
mod connect;
pub mod io;
mod pool;

pub(crate) use connect::{ConnectError, Progress};
pub(crate) use pool::{
    Acquired, ConnLease, Connected, Finish, Pool, PoolNote, Released, ReuseRules,
};

use std::fmt;
use std::net::SocketAddr;
use std::num::NonZeroU32;

use curl_alloc::{OutOfMemory, TryVec as _};

pub(crate) use self::buf::{RecvBuf, SendBuf};
use self::connect::ConnectMachine;
use self::io::{Recv, Sent, Socket};
use crate::id::Key;
use crate::time::Instant;

/// A connection's number in its pool, counting from 0 in the order the
/// pool made them: the `#N` of "Connection #N" (C's `connection_id`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ConnNumber(u64);

impl ConnNumber {
    pub(crate) fn get(self) -> u64 {
        self.0
    }
}

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
/// transfers may use one connection, one after the other, only if their
/// routes are equal.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub(crate) enum Route {
    /// No network: the protocol does its own I/O (C's
    /// `PROTOPT_NONETWORK`).
    Local,
    Tcp(Scheme, Destination),
}

/// The protocol a connection speaks, as reuse sees it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) struct Scheme {
    /// Its name, as "Reusing existing tcp: connection" names it.
    pub(crate) name: &'static str,
    /// Whether a connection is kept for another transfer once done
    /// (`PROTOPT_CONN_REUSE`).
    pub(crate) reuse: bool,
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
    route: Route,
    transport: Transport,
    /// The address connected to, and from; none without a network.
    remote: Option<SocketAddr>,
    local: Option<SocketAddr>,
    /// When its setup started (C's `conn->created`), and when it was
    /// found connected (TIMER_CONNECT's `connected_at`).
    created: Instant,
    connected_at: Instant,
    use_: Use,
    #[cfg_attr(
        not(test),
        expect(dead_code, reason = "the http protocol moves bytes from step 14b")
    )]
    rx: RecvBuf,
    #[cfg_attr(
        not(test),
        expect(dead_code, reason = "the http protocol moves bytes from step 14b")
    )]
    tx: SendBuf,
}

/// What a flush of a connection's queued bytes came to.
#[cfg_attr(
    not(test),
    expect(dead_code, reason = "the http protocol moves bytes from step 14b")
)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Flushed {
    /// Bytes the network took.
    pub(crate) sent: usize,
    /// Nothing is left to send.
    pub(crate) done: bool,
}

#[cfg_attr(
    not(test),
    expect(dead_code, reason = "the http protocol moves bytes from step 14b")
)]
impl Conn {
    fn socket(&self) -> &dyn Socket {
        match &self.transport {
            Transport::Tcp(socket) => &**socket,
            Transport::Local => unreachable!("a local connection moves no bytes"),
        }
    }

    /// Received bytes no request has used yet.
    pub(crate) fn rx_mut(&mut self) -> &mut RecvBuf {
        &mut self.rx
    }

    /// Bytes queued to send.
    pub(crate) fn tx_mut(&mut self) -> &mut SendBuf {
        &mut self.tx
    }

    /// Read once from the network, up to `max` bytes, behind what `rx`
    /// holds.
    pub(crate) fn recv(&mut self, max: usize) -> std::io::Result<Recv> {
        let socket = match &self.transport {
            Transport::Tcp(socket) => &**socket,
            Transport::Local => unreachable!("a local connection moves no bytes"),
        };
        // Borrowed apart from `rx`, which the read fills.
        let room = self
            .rx
            .room(max)
            .map_err(|_| std::io::ErrorKind::OutOfMemory)?;
        let got = socket.recv(room);
        let n = match got {
            Ok(Recv::Data(n)) => n.get(),
            Ok(Recv::Eof | Recv::WouldBlock) | Err(_) => 0,
        };
        self.rx.commit(max, n);
        got
    }

    /// Send what is queued, as much as the network takes now.
    pub(crate) fn flush(&mut self) -> std::io::Result<Flushed> {
        let mut sent = 0;
        while !self.tx.is_empty() {
            match self.socket().send(self.tx.pending())? {
                Sent::Bytes(n) => {
                    self.tx.sent(n.get());
                    sent += n.get();
                }
                Sent::WouldBlock => return Ok(Flushed { sent, done: false }),
            }
        }
        Ok(Flushed { sent, done: true })
    }
}

/// Whether a connection is leased.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Use {
    /// Leased this many times; once, as no connection is shared yet.
    Leased(NonZeroU32),
    /// Leased by no one since this time (C's `lastused`).
    Idle { since: Instant },
}
