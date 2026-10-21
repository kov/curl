//! Connections: what a transfer talks over, owned by the pool and leased to
//! transfers.
//!
//! A networkless connection is what `file:` leases, as C attaches a
//! connection to every transfer. A TCP one is set up by a
//! `ConnectMachine`, in the slot it keeps once established. `io` is the
//! engine's way to the network.

mod buf;
mod connect;
mod connect_to;
mod dns;
pub mod io;
mod pool;

pub(crate) use connect::{ConnectError, Failure, Found, Progress, Setup};
pub(crate) use connect_to::{BadVia, via};
pub(crate) use dns::{Answer, BadEntry, DnsCache, ListEntry, parse_entry};
pub(crate) use pool::{
    Acquired, ConnLease, Connected, Finish, Pool, PoolNote, Released, ReuseRules,
};

use std::fmt;
use std::net::SocketAddr;
use std::num::NonZeroU32;

use curl_alloc::TryRc;

use crate::options::IpVersion;

pub(crate) use self::buf::RecvBuf;
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

/// What a transfer needs of a connection, decided once per leg. A
/// connection serves another transfer only if its route serves the
/// transfer's.
#[derive(Clone, Debug)]
pub(crate) enum Route {
    /// No network: the protocol does its own I/O (C's
    /// `PROTOPT_NONETWORK`).
    Local,
    Tcp(Tcp),
}

impl Route {
    /// Whether a connection set up for this route may serve a transfer
    /// that needs `wanted` (`url_match_conn`, `url_match_destination`):
    /// the same origin through the same peer, and the same addresses
    /// unless the transfer takes any.
    pub(crate) fn serves(&self, wanted: &Route) -> bool {
        match (self, wanted) {
            (Route::Tcp(have), Route::Tcp(want)) => {
                // C compares the detours without their schemes
                // (`Curl_peer_same_destination`); each has its origin's.
                *have.origin == *want.origin
                    && have.via.as_deref() == want.via.as_deref()
                    && (want.ip == IpVersion::Any || want.ip == have.ip)
            }
            (Route::Local | Route::Tcp(..), Route::Local | Route::Tcp(..)) => false,
        }
    }
}

/// A route over TCP to `origin`, the peer shared by the transfer and the
/// connection; through `via` when a connect-to entry names another peer
/// for it (C's `via_peer`); over the addresses of `ip`.
#[derive(Clone, Debug)]
pub(crate) struct Tcp {
    pub(crate) origin: TryRc<Peer>,
    pub(crate) via: Option<TryRc<Peer>>,
    pub(crate) ip: IpVersion,
}

impl Tcp {
    /// The peer connected to (`Curl_conn_get_destination`).
    pub(crate) fn destination(&self) -> &Peer {
        self.via.as_deref().unwrap_or(&self.origin)
    }
}

/// The protocol a connection speaks, as reuse sees it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Scheme {
    /// Its name, as "Reusing existing tcp: connection" names it.
    pub(crate) name: &'static str,
    /// Whether a connection is kept for another transfer once done
    /// (`PROTOPT_CONN_REUSE`).
    pub(crate) reuse: bool,
}

/// Who a connection talks to (C's `struct Curl_peer`): the scheme, the
/// host as the URL names it, the port and the IPv6 zone. The transfer
/// and its connection share one.
#[derive(Debug)]
pub(crate) struct Peer {
    scheme: Scheme,
    /// An IPv6 address in brackets (`user_hostname`).
    host: Vec<u8>,
    port: u16,
    zone: Option<Vec<u8>>,
    /// The zone as a number, if it is one; 0 if not (`scopeid`).
    scope: u32,
}

impl Peer {
    pub(crate) fn new(scheme: Scheme, host: Vec<u8>, port: u16, zone: Option<Vec<u8>>) -> Peer {
        // A zone that is a plain number is the scope; a name's would be
        // its interface's index, which is not looked up yet.
        let scope = zone
            .as_deref()
            .filter(|z| !z.is_empty() && z.iter().all(u8::is_ascii_digit))
            .and_then(|z| std::str::from_utf8(z).ok()?.parse().ok())
            .unwrap_or(0);
        Peer {
            scheme,
            host,
            port,
            zone,
            scope,
        }
    }

    pub(crate) fn scheme(&self) -> Scheme {
        self.scheme
    }

    /// The host as the URL names it, an IPv6 address in brackets.
    pub(crate) fn shown(&self) -> &[u8] {
        &self.host
    }

    /// The host without an IPv6 address's brackets (`hostname`).
    pub(crate) fn name(&self) -> &[u8] {
        self.host
            .strip_prefix(b"[")
            .and_then(|h| h.strip_suffix(b"]"))
            .unwrap_or(&self.host)
    }

    /// Whether the host is an IPv6 address.
    pub(crate) fn ipv6(&self) -> bool {
        self.host.first() == Some(&b'[')
    }

    pub(crate) fn port(&self) -> u16 {
        self.port
    }

    /// The IPv6 zone, as given.
    pub(crate) fn zone(&self) -> Option<&[u8]> {
        self.zone.as_deref()
    }
}

/// The same peer (`Curl_peer_equal`): the same scheme, port and IPv6
/// zone, and the same host in any case.
impl PartialEq for Peer {
    fn eq(&self, other: &Peer) -> bool {
        self.scheme == other.scheme
            && self.port == other.port
            && self.ipv6() == other.ipv6()
            && self.name().eq_ignore_ascii_case(other.name())
            && self.scope == other.scope
            && (self.scope != 0 || self.zone == other.zone)
    }
}

impl Eq for Peer {}

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
    rx: RecvBuf,
    /// It carried a request before the one leasing it (C's
    /// `bits.reuse`).
    served: bool,
    /// It is not to be kept for another request (C's `connclose`), or
    /// its peer closed it, which no request can use again.
    close: bool,
}

impl Conn {
    fn socket(&self) -> &dyn Socket {
        match &self.transport {
            Transport::Tcp(socket) => &**socket,
            Transport::Local => unreachable!("a local connection moves no bytes"),
        }
    }

    /// Whether it carried a request before this one.
    pub(crate) fn reused(&self) -> bool {
        self.served
    }

    /// Keep it for no other request: it closes when its lease goes back.
    pub(crate) fn mark_close(&mut self) {
        self.close = true;
    }

    /// Received bytes no request has used yet.
    pub(crate) fn rx_mut(&mut self) -> &mut RecvBuf {
        &mut self.rx
    }

    /// Read once from the network, up to `max` bytes, behind what `rx`
    /// holds.
    pub(crate) fn recv(&mut self, max: usize) -> Result<Recv, RecvFailed> {
        let socket = match &self.transport {
            Transport::Tcp(socket) => &**socket,
            Transport::Local => unreachable!("a local connection moves no bytes"),
        };
        // Borrowed apart from `rx`, which the read fills.
        let room = self.rx.room(max).map_err(|_| RecvFailed::OutOfMemory)?;
        let got = socket.recv(room).map_err(RecvFailed::Os);
        let n = match got {
            Ok(Recv::Data(n)) => n.get(),
            Ok(Recv::Eof) => {
                // Shut down by the server, not reused (`multi_done`).
                self.close = true;
                0
            }
            Ok(Recv::WouldBlock) | Err(_) => 0,
        };
        self.rx.commit(max, n);
        got
    }

    /// Send from `bytes`, which is not empty, what the network takes now.
    pub(crate) fn send(&mut self, bytes: &[u8]) -> std::io::Result<Sent> {
        self.socket().send(bytes)
    }
}

/// Why reading from a connection failed.
#[derive(Debug)]
pub(crate) enum RecvFailed {
    /// No room could be made for what is read.
    OutOfMemory,
    /// The socket failed.
    Os(std::io::Error),
}

/// Whether a connection is leased.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Use {
    /// Leased this many times; once, as no connection is shared yet.
    Leased(NonZeroU32),
    /// Leased by no one since this time (C's `lastused`).
    Idle { since: Instant },
}

#[cfg(test)]
mod tests {
    use super::*;

    const HTTP: Scheme = Scheme {
        name: "http",
        reuse: true,
    };

    fn peer(host: &[u8], port: u16, zone: Option<&[u8]>) -> Peer {
        Peer::new(HTTP, host.to_vec(), port, zone.map(<[u8]>::to_vec))
    }

    /// Peers are the same as `Curl_peer_equal` finds them: the host in
    /// any case, the port, the scheme, and the zone by number or name.
    #[test]
    fn peers_compare_as_c_compares_them() {
        assert_eq!(
            peer(b"Example.COM", 80, None),
            peer(b"example.com", 80, None)
        );
        assert_ne!(
            peer(b"example.com", 80, None),
            peer(b"example.com", 81, None)
        );
        assert_ne!(
            peer(b"example.com", 80, None),
            peer(b"example.org", 80, None)
        );
        let other = Scheme {
            name: "tcp",
            reuse: true,
        };
        let tcp = Peer::new(other, b"example.com".to_vec(), 80, None);
        assert_ne!(tcp, peer(b"example.com", 80, None));
        let v6 = |zone| peer(b"[fe80::1]", 80, zone);
        assert_eq!(v6(Some(b"2")), v6(Some(b"02")), "one scope by number");
        assert_ne!(v6(Some(b"2")), v6(Some(b"3")));
        assert_eq!(v6(Some(b"eth0")), v6(Some(b"eth0")));
        assert_ne!(v6(Some(b"eth0")), v6(Some(b"eth1")), "unnumbered: by name");
        assert_ne!(v6(Some(b"eth0")), v6(None));
        assert_eq!(v6(None).name(), b"fe80::1");
        assert_eq!(v6(None).shown(), b"[fe80::1]");
        assert!(v6(None).ipv6() && !peer(b"fe80", 80, None).ipv6());
    }
}
