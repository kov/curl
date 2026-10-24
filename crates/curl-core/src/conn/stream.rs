//! The bytes of one connection: its socket, the layers they pass through
//! and what was received over it and not used yet. A connection being set
//! up through a proxy owns one, and the connection it becomes takes it
//! over, so both read and write the same way.

use std::io;
use std::net::SocketAddr;

use super::io::{Events, Recv, Sent, Sock, Socket};
use curl_alloc::OutOfMemory;

use super::layer::{Alive, Handshake, Layer, LayerAnswer, LayerCx, LayerQuery, LayerStack};
use super::{RecvBuf, RecvFailed};
use crate::components::Component;
use crate::error::ErrorKind;

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

    /// Its layers, for a test to push one on.
    #[cfg(any(test, feature = "test-util"))]
    pub(crate) fn layers_mut(&mut self) -> &mut LayerStack {
        &mut self.layers
    }

    /// Put `layer` on top of its layers, handing it what was received
    /// and not used, which the layer reads first: the bytes a proxy's
    /// answer came with are the peer's, for the layer that reads what the
    /// peer says next.
    pub(crate) fn push_over_received(
        &mut self,
        layer: impl FnOnce(Vec<u8>) -> Result<Box<dyn Layer>, OutOfMemory>,
    ) -> Result<(), OutOfMemory> {
        let layer = layer(self.rx.take())?;
        self.layers.push(layer)
    }

    /// Move its top layer's handshake on, the socket's sends and
    /// receives traced as `traced`, if given.
    pub(crate) fn connect(
        &mut self,
        cx: &mut dyn LayerCx,
        traced: Option<Component>,
    ) -> Result<Handshake, ErrorKind> {
        self.layers.connect(self.socket.socket(), cx, traced)
    }

    pub(crate) fn socket(&self) -> &dyn Socket {
        self.socket.socket()
    }

    /// The socket, for closing.
    pub(crate) fn into_socket(self) -> Sock {
        self.socket
    }

    /// Read once through the layers, up to `max` bytes, behind what was
    /// received and not used; the socket's receives traced as `traced`,
    /// if given.
    pub(crate) fn recv(
        &mut self,
        cx: &mut dyn LayerCx,
        max: usize,
        traced: Option<Component>,
    ) -> Result<Recv, RecvFailed> {
        let below = self.layers.over(self.socket.socket(), traced);
        self.rx.fill(max, |room| below.recv(cx, room))
    }

    /// Send from `bytes`, which is not empty, what the layers and the
    /// network take now; the socket's sends traced as `traced`, if given.
    pub(crate) fn send(
        &mut self,
        cx: &mut dyn LayerCx,
        bytes: &[u8],
        traced: Option<Component>,
    ) -> io::Result<Sent> {
        self.layers
            .over(self.socket.socket(), traced)
            .send(cx, bytes)
    }

    /// Whether bytes wait where a poll of the socket cannot see them: in
    /// a layer, or received and not used (`Curl_conn_data_pending`).
    pub(crate) fn data_pending(&mut self) -> bool {
        !self.rx.filled().is_empty() || self.layers.over(self.socket.socket(), None).data_pending()
    }

    /// What the transfer is to wait for on the socket, given what it
    /// wants, as the layers adjust it.
    pub(crate) fn adjust_pollset(&self, wanted: Events) -> Events {
        self.layers.adjust_pollset(wanted)
    }

    /// What its layers answer `q`, the topmost that does.
    pub(crate) fn query(&self, q: LayerQuery) -> Option<LayerAnswer> {
        self.layers.query(q)
    }

    /// The channel binding of the origin's TLS, if it has one.
    pub(crate) fn channel_binding(
        &self,
        notes: &mut dyn crate::tls::BindingNotes,
    ) -> Option<Result<Option<Vec<u8>>, ErrorKind>> {
        self.layers.channel_binding(notes)
    }

    /// Whether the connection seems usable, as its layers and its socket
    /// say. Nothing received waits unused on one that is idle: its last
    /// request used everything it read.
    pub(crate) fn is_alive(&mut self, cx: &mut dyn LayerCx) -> Alive {
        self.layers.over(self.socket.socket(), None).alive(cx)
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

    /// Move its shutdown on: each layer from the top, past the `shut`
    /// done already, one at a time, then the socket's own, the 1 KB drain
    /// (`Curl_cshutdn_try_once_idx`). A layer that waits ends the try; one
    /// that fails ends the shutdown.
    pub(crate) fn shutdown(
        &mut self,
        cx: &mut dyn LayerCx,
        shut: &mut usize,
    ) -> Result<Handshake, ErrorKind> {
        if self.layers.shutdown(self.socket.socket(), cx, shut)? == Handshake::Waiting {
            return Ok(Handshake::Waiting);
        }
        self.drain();
        Ok(Handshake::Done)
    }

    /// What it waits on while it shuts down, `shut` of its layers done:
    /// what the others say, from the top, with nothing wanted to start
    /// from (`Curl_conn_adjust_pollset` on a chain in shutdown).
    pub(crate) fn shutdown_pollset(&self, shut: usize) -> Events {
        self.layers.shutdown_pollset(shut)
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
