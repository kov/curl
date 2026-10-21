//! The connection pool: the owner of every connection, busy or idle, and
//! the only issuer and consumer of leases (`lib/conncache.c`).

use std::net::SocketAddr;

use curl_alloc::OutOfMemory;

use super::connect::{ConnectError, ConnectMachine, Drove, Progress};
use super::io::{Events, Net, Socket};
use super::{Conn, ConnId, ConnNumber, ConnSlot, Route, Transport};
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
    Closed(ConnNumber),
    /// Closed at once: the transfer ended prematurely.
    Terminated(ConnNumber),
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

    /// A new connection for `route`, leased to the caller: open at once
    /// without a network, set up by `Pool::connect` over one.
    pub(crate) fn acquire(&mut self, route: Route, now: Instant) -> Result<ConnLease, OutOfMemory> {
        let number = ConnNumber(self.next_number);
        let slot = match route {
            Route::Local => ConnSlot::Open(Conn {
                number,
                transport: Transport::Local,
                remote: None,
                local: None,
                connected_at: now,
            }),
            Route::Tcp(dest) => ConnSlot::Connecting(ConnectMachine::new(number, dest)),
        };
        let id = self.conns.reserve()?.fill(slot);
        self.next_number += 1;
        Ok(ConnLease { id })
    }

    /// Move the leased connection's setup on by one event. A connection
    /// already up says so again.
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
                            let up = established(&conn);
                            (ConnSlot::Open(conn), Ok(up))
                        }
                        Err(e) => (ConnSlot::Failed(number), Err(e)),
                    }
                }
                ConnSlot::Open(conn) => {
                    let up = established(&conn);
                    (ConnSlot::Open(conn), Ok(up))
                }
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
    /// `multi_done_locked` does.
    pub(crate) fn release(
        &mut self,
        lease: ConnLease,
        finish: Finish,
        net: &mut dyn Net,
    ) -> Released {
        let id = lease.id;
        std::mem::forget(lease);
        // No route allows sharing or reuse yet: a connection has one lease
        // and closes with it. Sharing, keeping a connection idle for the
        // next transfer, and the reasons C closes one anyway, come with
        // the pool's reuse.
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
                let number = conn.number;
                match conn.transport {
                    Transport::Local => {}
                    Transport::Tcp(socket) => net.close(socket),
                }
                number
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
    #[cfg(any(test, debug_assertions))]
    pub(crate) fn len(&self) -> u32 {
        self.conns.len()
    }
}

/// What an established connection reports of itself.
fn established(conn: &Conn) -> Connected {
    Connected::Established {
        remote: conn.remote.expect("a connection set up over the network"),
        local: conn.local,
        at: conn.connected_at,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::conn::Destination;
    use crate::conn::io::{FakeNet, Peer};
    use crate::time::{Clock as _, ManualClock};

    fn net() -> (FakeNet, Instant) {
        let clock = ManualClock::new().unwrap();
        let now = clock.now();
        let at = |port| SocketAddr::from(([127, 0, 0, 1], port));
        let net = FakeNet::new(clock)
            .with_peer(at(1), Peer::Accepts)
            .with_peer(at(2), Peer::Refuses)
            .with_peer(at(3), Peer::Silent);
        (net, now)
    }

    fn tcp(port: u16) -> Route {
        Route::Tcp(Destination::new(b"127.0.0.1", port).unwrap())
    }

    #[test]
    fn local_connections_are_numbered_and_closed_when_released() {
        let (mut net, now) = net();
        let mut pool = Pool::new().unwrap();
        let a = pool.acquire(Route::Local, now).unwrap();
        let b = pool.acquire(Route::Local, now).unwrap();
        assert_ne!(a.id(), b.id(), "a local connection is never shared");
        assert_eq!(pool.get(&a).number.to_string(), "#0");
        assert_eq!(pool.get(&b).number.to_string(), "#1");
        assert_eq!(pool.len(), 2);
        let a_id = a.id();
        assert_eq!(
            pool.release(a, Finish::default(), &mut net),
            Released::Closed(ConnNumber(0))
        );
        assert!(pool.get_conn(a_id).is_none());
        assert_eq!(pool.get_conn(b.id()).map(|c| c.number), Some(ConnNumber(1)));
        let premature = Finish { premature: true };
        assert_eq!(
            pool.release(b, premature, &mut net),
            Released::Terminated(ConnNumber(1))
        );
        assert_eq!(pool.len(), 0);
        // Numbers are never reused.
        let c = pool.acquire(Route::Local, now).unwrap();
        assert_eq!(pool.get(&c).number.to_string(), "#2");
        assert_eq!(
            pool.release(c, Finish::default(), &mut net),
            Released::Closed(ConnNumber(2))
        );
    }

    /// A setup tries its address, waits, and is established in the slot
    /// it started in; its socket is the pool's to wait on until then.
    #[test]
    fn a_tcp_connection_is_set_up_in_its_slot() {
        let (mut net, now) = net();
        let mut pool = Pool::new().unwrap();
        let lease = pool.acquire(tcp(1), now).unwrap();
        let id = lease.id();
        let mut waited = 0;
        pool.sockets(|_, _| waited += 1);
        assert_eq!(waited, 0, "nothing open before the first drive");
        let tried = pool.connect(&lease, &mut net, now).unwrap();
        let to = SocketAddr::from(([127, 0, 0, 1], 1));
        assert!(matches!(tried, Connected::Connecting(Progress::Trying(a)) if a == to));
        let mut watched = Vec::new();
        pool.sockets(|s, e| watched.push((s.key().get(), e)));
        assert_eq!(watched, [(1000, Events::OUT)]);
        assert!(pool.get_conn(id).is_none(), "not up yet");
        let up = pool.connect(&lease, &mut net, now).unwrap();
        let Connected::Established { remote, local, at } = up else {
            panic!("{up:?}");
        };
        assert_eq!((remote, at), (to, now));
        assert_eq!(local, Some(SocketAddr::from(([127, 0, 0, 1], 40000))));
        assert_eq!(pool.get_conn(id).map(|c| c.number), Some(ConnNumber(0)));
        let mut waited = 0;
        pool.sockets(|_, _| waited += 1);
        assert_eq!(waited, 0, "an open connection waits on nothing yet");
        assert_eq!(
            pool.release(lease, Finish::default(), &mut net),
            Released::Closed(ConnNumber(0))
        );
        // The socket was closed: its number is free again.
        let (s, _) = net.connect(to).unwrap();
        assert_eq!(s.key().get(), 1000);
        net.close(s);
    }

    /// A refused attempt closes its socket and says from where it tried;
    /// a silent one waits.
    #[test]
    fn refused_and_silent_attempts() {
        let (mut net, now) = net();
        let mut pool = Pool::new().unwrap();
        let refused = pool.acquire(tcp(2), now).unwrap();
        pool.connect(&refused, &mut net, now).unwrap();
        let err = pool.connect(&refused, &mut net, now).unwrap_err();
        let ConnectError::Attempt {
            remote,
            local,
            error,
        } = err
        else {
            panic!("{err:?}");
        };
        assert_eq!(remote.port(), 2);
        assert_eq!(local.map(|l| l.port()), Some(40000));
        assert_eq!(error.kind(), std::io::ErrorKind::ConnectionRefused);
        let mut waited = 0;
        pool.sockets(|_, _| waited += 1);
        assert_eq!(waited, 0, "the failed attempt's socket is closed");
        let silent = pool.acquire(tcp(3), now).unwrap();
        pool.connect(&silent, &mut net, now).unwrap();
        for _ in 0..3 {
            let waiting = pool.connect(&silent, &mut net, now).unwrap();
            assert!(matches!(waiting, Connected::Connecting(Progress::Waiting)));
        }
        let premature = Finish { premature: true };
        assert_eq!(
            pool.release(refused, premature, &mut net),
            Released::Terminated(ConnNumber(0))
        );
        assert_eq!(
            pool.release(silent, premature, &mut net),
            Released::Terminated(ConnNumber(1))
        );
        // Both sockets were closed.
        let (s, _) = net.connect(SocketAddr::from(([127, 0, 0, 1], 1))).unwrap();
        assert_eq!(s.key().get(), 1000);
        net.close(s);
    }

    /// A name with no address, and an address with no peer, fail before
    /// any socket is polled.
    #[test]
    fn unresolved_names_and_immediate_failures() {
        let (mut net, now) = net();
        let mut pool = Pool::new().unwrap();
        let named = pool
            .acquire(
                Route::Tcp(Destination::new(b"example.com", 80).unwrap()),
                now,
            )
            .unwrap();
        let err = pool.connect(&named, &mut net, now).unwrap_err();
        assert!(matches!(err, ConnectError::Unresolved), "{err:?}");
        let nobody = pool.acquire(tcp(9), now).unwrap();
        let err = pool.connect(&nobody, &mut net, now).unwrap_err();
        assert!(
            matches!(err, ConnectError::Immediate { remote, .. } if remote.port() == 9),
            "{err:?}"
        );
        let premature = Finish { premature: true };
        for lease in [named, nobody] {
            assert!(matches!(
                pool.release(lease, premature, &mut net),
                Released::Terminated(_)
            ));
        }
        assert_eq!(pool.len(), 0);
    }

    #[test]
    #[cfg(debug_assertions)]
    #[should_panic = "dropped, not released"]
    fn a_dropped_lease_is_caught() {
        let mut pool = Pool::new().unwrap();
        drop(
            pool.acquire(Route::Local, ManualClock::new().unwrap().now())
                .unwrap(),
        );
    }
}
