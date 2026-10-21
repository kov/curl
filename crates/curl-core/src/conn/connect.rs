//! Setting a connection up: the name resolved, then attempts raced to its
//! addresses until one connects (`lib/connect.c`, `cf-ip-happy.c`,
//! `cf-socket.c`).
//!
//! Each stage owns what the one before produced. A drive moves the machine
//! on by at most one event, which it returns for the transfer to trace:
//! the machine never reaches a transfer, so it can be driven while the
//! pool holding it is borrowed.

use std::io;
use std::net::{IpAddr, Ipv6Addr, SocketAddr};

use std::num::NonZeroU32;

use super::io::{Connect, Events, Net, Socket, SocketPoll};
use super::{Conn, ConnNumber, Destination, RecvBuf, Route, Scheme, Transport, Use};
use crate::time::Instant;

/// A connection being set up.
#[derive(Debug)]
pub(crate) struct ConnectMachine {
    number: ConnNumber,
    scheme: Scheme,
    dest: Destination,
    /// When the setup started (C's `conn->created`).
    created: Instant,
    stage: Stage,
}

#[derive(Debug)]
enum Stage {
    /// The destination's name is to be resolved.
    Resolving,
    /// An attempt is connecting to an address.
    Racing(Attempt),
}

/// A socket connecting to one address.
#[derive(Debug)]
struct Attempt {
    remote: SocketAddr,
    socket: Box<dyn Socket>,
}

/// What a drive did.
#[derive(Debug)]
pub(crate) enum Drove {
    /// Still setting up: drive it again when `wants` comes.
    Connecting(ConnectMachine, Progress),
    /// The connection is up.
    Established(Conn),
}

/// Something a setup said, or nothing new.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Progress {
    /// An attempt started on `0`.
    Trying(SocketAddr),
    /// Nothing until the socket is ready.
    Waiting,
}

/// Why a setup failed; any socket it had is closed.
#[derive(Debug)]
pub(crate) enum ConnectError {
    /// The name has no address this build can find.
    Unresolved,
    /// Connecting to `remote` failed at once, before any socket was
    /// polled.
    Immediate {
        remote: SocketAddr,
        error: io::Error,
    },
    /// The last attempt, to `remote` from `local`, failed.
    Attempt {
        remote: SocketAddr,
        local: Option<SocketAddr>,
        error: io::Error,
    },
}

impl ConnectMachine {
    pub(crate) fn new(
        number: ConnNumber,
        scheme: Scheme,
        dest: Destination,
        created: Instant,
    ) -> ConnectMachine {
        ConnectMachine {
            number,
            scheme,
            dest,
            created,
            stage: Stage::Resolving,
        }
    }

    pub(crate) fn number(&self) -> ConnNumber {
        self.number
    }

    /// The socket of the attempt under way, if one is.
    pub(crate) fn socket(&self) -> Option<&dyn Socket> {
        match &self.stage {
            Stage::Resolving => None,
            Stage::Racing(a) => Some(&*a.socket),
        }
    }

    /// Move the setup on by one event.
    pub(crate) fn drive(self, net: &mut dyn Net, now: Instant) -> Result<Drove, ConnectError> {
        let ConnectMachine {
            number,
            scheme,
            dest,
            created,
            stage,
        } = self;
        let next = |dest, stage| ConnectMachine {
            number,
            scheme,
            dest,
            created,
            stage,
        };
        match stage {
            Stage::Resolving => {
                let ip = literal(&dest.host).ok_or(ConnectError::Unresolved)?;
                let remote = SocketAddr::new(ip, dest.port);
                let socket = match net.connect(remote) {
                    Ok((socket, Connect::InProgress | Connect::Done)) => socket,
                    Err(error) => return Err(ConnectError::Immediate { remote, error }),
                };
                let stage = Stage::Racing(Attempt { remote, socket });
                Ok(Drove::Connecting(
                    next(dest, stage),
                    Progress::Trying(remote),
                ))
            }
            Stage::Racing(a) => {
                // Writable once the connect is decided, either way
                // (`SOCKET_WRITABLE(sock, 0)`).
                let mut watch = [SocketPoll::new(&*a.socket, Events::OUT)];
                let ready = match net.poll(&mut watch, &mut [], std::time::Duration::ZERO) {
                    Ok(_) => !watch[0].revents().is_empty(),
                    Err(error) => return Err(a.fail(net, error)),
                };
                if !ready {
                    return Ok(Drove::Connecting(
                        next(dest, Stage::Racing(a)),
                        Progress::Waiting,
                    ));
                }
                match a.socket.take_error() {
                    Ok(None) => {
                        let local = a.socket.local_addr().ok();
                        Ok(Drove::Established(Conn {
                            number,
                            route: Route::Tcp(scheme, dest),
                            transport: Transport::Tcp(a.socket),
                            remote: Some(a.remote),
                            local,
                            created,
                            connected_at: now,
                            use_: Use::Leased(NonZeroU32::MIN),
                            rx: RecvBuf::default(),
                            served: false,
                            close: false,
                        }))
                    }
                    Ok(Some(error)) | Err(error) => Err(a.fail(net, error)),
                }
            }
        }
    }

    /// End the setup, closing what it has open.
    pub(crate) fn close(self, net: &mut dyn Net) {
        match self.stage {
            Stage::Resolving => {}
            Stage::Racing(a) => net.close(a.socket),
        }
    }
}

impl Attempt {
    /// The attempt failed with `error`: its socket is closed, its local
    /// address read first, as C reads it for the trace.
    fn fail(self, net: &mut dyn Net, error: io::Error) -> ConnectError {
        let local = self.socket.local_addr().ok();
        net.close(self.socket);
        ConnectError::Attempt {
            remote: self.remote,
            local,
            error,
        }
    }
}

/// `host` as an address if it is one, as the URL holds it: an IPv4
/// address dotted, an IPv6 one in brackets.
fn literal(host: &[u8]) -> Option<IpAddr> {
    let text = std::str::from_utf8(host).ok()?;
    if let Some(inner) = text.strip_prefix('[').and_then(|t| t.strip_suffix(']')) {
        return inner.parse::<Ipv6Addr>().ok().map(IpAddr::V6);
    }
    text.parse::<std::net::Ipv4Addr>().ok().map(IpAddr::V4)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn literals_are_addresses() {
        assert_eq!(literal(b"127.0.0.1"), Some(IpAddr::from([127, 0, 0, 1])));
        assert_eq!(literal(b"[::1]"), Some(IpAddr::V6(Ipv6Addr::LOCALHOST)));
        assert_eq!(literal(b"::1"), None, "the URL keeps the brackets");
        assert_eq!(literal(b"[127.0.0.1]"), None);
        assert_eq!(literal(b"example.com"), None);
        assert_eq!(literal(b"localhost"), None);
    }
}
