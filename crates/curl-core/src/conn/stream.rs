//! The bytes of one connection: its socket, the layers they pass through
//! and what was received over it and not used yet. A connection being set
//! up through a proxy owns one, and the connection it becomes takes it
//! over, so both read and write the same way.

use std::io;
use std::net::SocketAddr;

use super::io::{Events, Recv, Sent, Sock, Socket};
use super::layer::{Alive, LayerCx, LayerStack};
use super::{RecvBuf, RecvFailed};

#[derive(Debug)]
pub(crate) struct Stream {
    socket: Sock,
    layers: LayerStack,
    rx: RecvBuf,
}

impl Stream {
    pub(crate) fn new(socket: Sock) -> Stream {
        Stream {
            socket,
            layers: LayerStack::default(),
            rx: RecvBuf::default(),
        }
    }

    /// Its layers, to push one on.
    #[cfg_attr(
        not(test),
        expect(dead_code, reason = "TLS pushes its layer, step 43; tests push theirs")
    )]
    pub(crate) fn layers_mut(&mut self) -> &mut LayerStack {
        &mut self.layers
    }

    pub(crate) fn socket(&self) -> &dyn Socket {
        self.socket.socket()
    }

    /// The socket, for closing.
    pub(crate) fn into_socket(self) -> Sock {
        self.socket
    }

    /// Read once through the layers, up to `max` bytes, behind what was
    /// received and not used.
    pub(crate) fn recv(&mut self, cx: &mut dyn LayerCx, max: usize) -> Result<Recv, RecvFailed> {
        let below = self.layers.over(self.socket.socket());
        self.rx.fill(max, |room| below.recv(cx, room))
    }

    /// Send from `bytes`, which is not empty, what the layers and the
    /// network take now.
    pub(crate) fn send(&mut self, cx: &mut dyn LayerCx, bytes: &[u8]) -> io::Result<Sent> {
        self.layers.over(self.socket.socket()).send(cx, bytes)
    }

    /// Whether bytes wait in a layer, where a poll of the socket cannot
    /// see them (`Curl_conn_data_pending`).
    pub(crate) fn data_pending(&mut self) -> bool {
        self.layers.over(self.socket.socket()).data_pending()
    }

    /// What the transfer is to wait for on the socket, given what it
    /// wants, as the layers adjust it.
    pub(crate) fn adjust_pollset(&self, wanted: Events) -> Events {
        self.layers.adjust_pollset(wanted)
    }

    /// Whether the connection seems usable, as its layers and its socket
    /// say. Nothing received waits unused on one that is idle: its last
    /// request used everything it read.
    pub(crate) fn is_alive(&mut self, cx: &mut dyn LayerCx) -> Alive {
        self.layers.over(self.socket.socket()).alive(cx)
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

    /// Read and drop up to 1 KB of what the peer sent, before a clean
    /// close, whatever the read says, as C does (`cf_socket_shutdown`).
    pub(crate) fn drain(&self) {
        let mut buf = [0u8; 1024];
        // A failure, or nothing to read, leaves the close as it was.
        let _ = self.socket().recv(&mut buf);
    }

    /// The connection's end here, if the system says.
    pub(crate) fn local_addr(&self) -> Option<SocketAddr> {
        self.socket.socket().local_addr().ok()
    }
}
