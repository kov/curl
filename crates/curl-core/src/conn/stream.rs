//! The bytes of one connection: its socket, and what was received over it
//! and not used yet. A connection being set up through a proxy owns one,
//! and the connection it becomes takes it over, so both read and write the
//! same way.

use std::io;
use std::net::SocketAddr;

use super::io::{Recv, Sent, Sock, Socket};
use super::{RecvBuf, RecvFailed};

#[derive(Debug)]
pub(crate) struct Stream {
    socket: Sock,
    rx: RecvBuf,
}

impl Stream {
    pub(crate) fn new(socket: Sock) -> Stream {
        Stream {
            socket,
            rx: RecvBuf::default(),
        }
    }

    pub(crate) fn socket(&self) -> &dyn Socket {
        self.socket.socket()
    }

    /// The socket, for closing.
    pub(crate) fn into_socket(self) -> Sock {
        self.socket
    }

    /// Read once, up to `max` bytes, behind what was received and not
    /// used.
    pub(crate) fn recv(&mut self, max: usize) -> Result<Recv, RecvFailed> {
        let socket = self.socket.socket();
        self.rx.fill(max, |room| socket.recv(room))
    }

    /// Send from `bytes`, which is not empty, what the network takes now.
    pub(crate) fn send(&mut self, bytes: &[u8]) -> io::Result<Sent> {
        self.socket.socket().send(bytes)
    }

    /// What was received and not used.
    pub(crate) fn received(&self) -> &[u8] {
        self.rx.filled()
    }

    /// The first `n` bytes received were used.
    pub(crate) fn consume(&mut self, n: usize) {
        self.rx.consume(n);
    }

    pub(crate) fn rx_mut(&mut self) -> &mut RecvBuf {
        &mut self.rx
    }

    /// The connection's end here, if the system says.
    pub(crate) fn local_addr(&self) -> Option<SocketAddr> {
        self.socket.socket().local_addr().ok()
    }
}
