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

/// The socket of a QUIC connection dialed straight to its peer: its
/// datagrams go to the socket with nothing between, and nothing is
/// received there that the connection does not read itself (C's UDP
/// socket filter under the QUIC one). QUIC through a tunnel is over the
/// tunnel's `Stream` instead.
#[derive(Debug)]
pub(crate) struct Datagrams {
    socket: Sock,
}

impl Datagrams {
    pub(crate) fn new(socket: Sock) -> Datagrams {
        Datagrams { socket }
    }

    pub(crate) fn socket(&self) -> &dyn Socket {
        self.socket.socket()
    }

    /// The socket, for closing.
    pub(crate) fn into_socket(self) -> Sock {
        self.socket
    }

    /// The socket, its sends and receives traced as `traced`, if given.
    pub(crate) fn below(&mut self, traced: Option<Component>) -> super::layer::Below<'_> {
        super::layer::Below::bare(self.socket.socket(), traced)
    }

    /// Whether the connection seems usable, as its socket says.
    pub(crate) fn is_alive(&mut self, cx: &mut dyn LayerCx) -> Alive {
        self.below(None).alive(cx)
    }

    /// The connection's end here, if the system says.
    pub(crate) fn local_addr(&self) -> Option<SocketAddr> {
        self.socket.socket().local_addr().ok()
    }
}

#[derive(Debug)]
pub(crate) struct Stream {
    socket: Sock,
    layers: LayerStack,
    rx: RecvBuf,
    /// Its socket has received a byte (`got_first_byte`).
    heard: std::cell::Cell<bool>,
}

impl Stream {
    pub(crate) fn new(socket: Sock) -> Stream {
        Stream {
            socket,
            layers: LayerStack::default(),
            rx: RecvBuf::default(),
            heard: std::cell::Cell::new(false),
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
        self.layers
            .connect(self.socket.socket(), cx, traced, Some(&self.heard))
    }

    /// Move the goodbye of the origin's TLS on, as `goodbye` says, its
    /// layer taken off once over or failed: what is sent and received
    /// after goes in clear. The socket's sends and receives traced as
    /// `traced`, if given.
    pub(crate) fn clear_tls(
        &mut self,
        cx: &mut dyn LayerCx,
        traced: Option<Component>,
        goodbye: crate::tls::Goodbye,
    ) -> Result<Handshake, ErrorKind> {
        self.layers
            .clear_tls(self.socket.socket(), cx, traced, Some(&self.heard), goodbye)
    }

    /// Its layers over its socket, for a handshake that reads and writes
    /// past what was received and not used; the socket's sends and
    /// receives traced as `traced`, if given.
    pub(crate) fn below(&mut self, traced: Option<Component>) -> super::layer::Below<'_> {
        self.layers
            .over(self.socket.socket(), traced, Some(&self.heard))
    }

    pub(crate) fn socket(&self) -> &dyn Socket {
        self.socket.socket()
    }

    /// Its socket, for a library that reads and writes it itself; none
    /// while a layer works on its bytes, or bytes received wait unused:
    /// the library would read past them.
    pub(crate) fn bare_socket(&self) -> Option<&dyn Socket> {
        (self.layers.is_empty() && self.rx.filled().is_empty()).then(|| self.socket.socket())
    }

    /// Its socket has received a byte, as C's socket filter answers how
    /// long that took once it has (`CF_QUERY_CONNECT_REPLY_MS`).
    pub(crate) fn heard(&self) -> bool {
        self.heard.get()
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
        let below = self
            .layers
            .over(self.socket.socket(), traced, Some(&self.heard));
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
            .over(self.socket.socket(), traced, Some(&self.heard))
            .send(cx, bytes)
    }

    /// Whether bytes wait where a poll of the socket cannot see them: in
    /// a layer, or received and not used (`Curl_conn_data_pending`).
    pub(crate) fn data_pending(&mut self) -> bool {
        !self.rx.filled().is_empty()
            || self
                .layers
                .over(self.socket.socket(), None, Some(&self.heard))
                .data_pending()
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

    /// The latest session of the origin's TLS, if it keeps a copy.
    pub(crate) fn latest_session(&self) -> Option<&crate::tls::TlsTicket> {
        self.layers.latest_session()
    }

    /// Whether the connection seems usable, as its layers and its socket
    /// say. Nothing received waits unused on one that is idle: its last
    /// request used everything it read.
    pub(crate) fn is_alive(&mut self, cx: &mut dyn LayerCx) -> Alive {
        self.layers
            .over(self.socket.socket(), None, Some(&self.heard))
            .alive(cx)
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

    /// Say what its layers put in that pollset, as C's filters do.
    pub(crate) fn say_shutdown_pollset(&self, shut: usize, cx: &mut dyn LayerCx) {
        let fd = self.socket().key().get();
        self.layers.say_shutdown_pollset(shut, fd, cx);
    }

    /// Read and drop up to 1 KB of what the peer sent, before a clean
    /// close, whatever the read says, as C does (`cf_socket_shutdown`).
    /// The socket is made nonblocking first, as a library it was lent to
    /// (libssh, sharing its file description) may have left it blocking;
    /// one that cannot be is not read.
    pub(crate) fn drain(&self) {
        if self.socket().set_nonblocking().is_err() {
            return;
        }
        let mut buf = [0u8; 1024];
        // A failure, or nothing to read, leaves the close as it was.
        let _ = self.socket().recv(&mut buf);
    }

    /// The connection's end here, if the system says.
    pub(crate) fn local_addr(&self) -> Option<SocketAddr> {
        self.socket.socket().local_addr().ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::conn::io::{Closer, Conversation, FakeNet, Net as _, Peer, dial};
    use crate::conn::layer::Silent;
    use crate::time::{Clock as _, ManualClock};

    /// The socket is handed to a library only while no byte received
    /// waits unused in the stream: the library would read past it.
    #[test]
    fn a_socket_with_bytes_held_is_not_handed_over() {
        let clock = ManualClock::new().unwrap();
        let at = SocketAddr::from(([127, 0, 0, 1], 22));
        let talk = Conversation::replies(&[b"SSH-2.0-x\r\n"], false).greeting();
        let mut net = FakeNet::new(clock.clone())
            .with_peer(at, Peer::Accepts)
            .with_conversation(at, talk);
        let mut stream = Stream::new(Sock::new(dial(&mut net, at), Closer::System));
        assert!(stream.bare_socket().is_some(), "nothing received yet");
        let mut cx = Silent(clock.now());
        assert!(matches!(stream.recv(&mut cx, 4, None), Ok(Recv::Data(_))));
        assert!(stream.bare_socket().is_none(), "the banner's start is held");
        let held = stream.received().len();
        stream.consume(held);
        assert!(stream.bare_socket().is_some(), "all of it used");
        net.close(stream.into_socket());
    }
}
