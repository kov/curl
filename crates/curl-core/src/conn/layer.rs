//! The layers a connection's bytes pass through between the socket and
//! the protocol (C's connection filters, `cfilters.h`), as a pull chain: a
//! read asks the top layer for at most the caller's length, and each layer
//! reads from the one below it as it needs, down to the socket. A layer
//! that works on the bytes (TLS) is boxed on the stream; those that only
//! pass them once connected (SOCKS, an HTTP proxy's tunnel) are kinds kept
//! inline, so a stream over TCP, a SOCKS proxy or a tunnel allocates
//! nothing for its layers.

use std::fmt;
use std::io;
use std::time::Duration;

use curl_alloc::{OutOfMemory, TryVec as _, try_box};

use super::io::{Events, Recv, Sent, Socket, SocketPoll, poll_together};
use crate::components::Component;
use crate::error::ErrorKind;
use crate::time::Instant;

/// What a layer's handshake, or its shutdown, came to.
#[expect(dead_code, reason = "TLS's handshake and shutdown, step 43")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Handshake {
    Done,
    /// It waits for the socket.
    Waiting,
}

/// Whether a connection seems usable, as its layers and its socket say
/// (`Curl_conn_is_alive`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Alive {
    Dead,
    /// Usable; with input waiting, which an idle HTTP/1 connection must
    /// not have.
    Alive {
        input_pending: bool,
    },
}

/// A question one layer asks another (C's `cf->cft->query`); TLS's come
/// with it.
#[expect(dead_code, reason = "TLS's ALPN and certificates, step 43")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum LayerQuery {}

/// What a layer answers a `LayerQuery`.
#[expect(dead_code, reason = "TLS's ALPN and certificates, step 43")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum LayerAnswer {}

/// What a layer reaches while it works: the time, and the trace of the
/// transfer it works for. An argument, never stored. A pool's section,
/// which works for no transfer, has a silent one.
pub(crate) trait LayerCx {
    fn now(&self) -> Instant;

    /// Whether `component`'s lines are traced.
    #[expect(dead_code, reason = "the setup's trace, step 40h")]
    fn traces(&self, component: Component) -> bool;

    /// Trace a line of `component`'s, if it is.
    #[expect(dead_code, reason = "the setup's trace, step 40h")]
    fn of(&mut self, component: Component, line: fmt::Arguments<'_>);
}

/// The context of work done for no transfer: it traces nothing, as C's
/// internal handle is not traced.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Silent(pub(crate) Instant);

impl LayerCx for Silent {
    fn now(&self) -> Instant {
        self.0
    }

    fn traces(&self, _: Component) -> bool {
        false
    }

    fn of(&mut self, _: Component, _: fmt::Arguments<'_>) {}
}

/// A layer that works on a connection's bytes (C's `Curl_cftype`). Its
/// `destroy` is `Drop`; its `cntrl` codes are methods of their own.
pub(crate) trait Layer: Send + fmt::Debug {
    /// Move its handshake on. None has one yet: TLS's comes with it.
    #[expect(dead_code, reason = "TLS's handshake, step 43")]
    fn connect(
        &mut self,
        _cx: &mut dyn LayerCx,
        _below: Below<'_>,
    ) -> Result<Handshake, ErrorKind> {
        Ok(Handshake::Done)
    }

    /// Read into `buf`, which is not empty, at most its length, from
    /// what it holds or from below.
    fn recv(&mut self, cx: &mut dyn LayerCx, below: Below<'_>, buf: &mut [u8]) -> io::Result<Recv>;

    /// Send from `bytes`, which is not empty, through the layers below.
    fn send(&mut self, cx: &mut dyn LayerCx, below: Below<'_>, bytes: &[u8]) -> io::Result<Sent>;

    /// What the transfer is to wait for on the socket, given what it
    /// wants (TLS wants to write while it reads).
    fn adjust_pollset(&self, wanted: Events) -> Events {
        wanted
    }

    /// Whether it, or a layer below, holds bytes a poll of the socket
    /// cannot see.
    fn data_pending(&self, below: Below<'_>) -> bool {
        below.data_pending()
    }

    /// Whether the connection seems usable, asking below.
    fn is_alive(&mut self, cx: &mut dyn LayerCx, below: Below<'_>) -> Alive {
        below.alive(cx)
    }

    /// Move its shutdown on. None has one yet: TLS's comes with it.
    #[expect(dead_code, reason = "TLS's shutdown, step 43")]
    fn shutdown(
        &mut self,
        _cx: &mut dyn LayerCx,
        _below: Below<'_>,
    ) -> Result<Handshake, ErrorKind> {
        Ok(Handshake::Done)
    }

    /// Answer another layer's question, if it can. None asks one yet.
    #[expect(dead_code, reason = "TLS's ALPN and certificates, step 43")]
    fn query(&self, q: LayerQuery) -> Option<LayerAnswer> {
        match q {}
    }
}

/// The layers below one, then the socket: the stack split at the layer
/// being called, so a layer reads and writes the ones below without
/// aliasing itself.
pub(crate) struct Below<'a> {
    /// Bottom first.
    layers: &'a mut [Box<dyn Layer>],
    socket: &'a dyn Socket,
}

impl Below<'_> {
    pub(crate) fn recv(self, cx: &mut dyn LayerCx, buf: &mut [u8]) -> io::Result<Recv> {
        match self.layers.split_last_mut() {
            Some((top, layers)) => top.recv(cx, Below { layers, ..self }, buf),
            None => self.socket.recv(buf),
        }
    }

    pub(crate) fn send(self, cx: &mut dyn LayerCx, bytes: &[u8]) -> io::Result<Sent> {
        match self.layers.split_last_mut() {
            Some((top, layers)) => top.send(cx, Below { layers, ..self }, bytes),
            None => self.socket.send(bytes),
        }
    }

    /// The socket holds nothing a poll cannot see.
    pub(crate) fn data_pending(self) -> bool {
        match self.layers.split_last_mut() {
            Some((top, layers)) => top.data_pending(Below { layers, ..self }),
            None => false,
        }
    }

    /// The socket polled at once (`cf_socket_conn_is_alive`): an error,
    /// a hang-up or an error event is dead; anything to read, input
    /// pending.
    pub(crate) fn alive(self, cx: &mut dyn LayerCx) -> Alive {
        match self.layers.split_last_mut() {
            Some((top, layers)) => top.is_alive(cx, Below { layers, ..self }),
            None => {
                let mut watch = [SocketPoll::new(self.socket, Events::IN)];
                match poll_together(&mut watch, &mut [], Duration::ZERO) {
                    Ok(_) if watch[0].revents().is_empty() => Alive::Alive {
                        input_pending: false,
                    },
                    Ok(_) if watch[0].revents() == Events::IN => Alive::Alive {
                        input_pending: true,
                    },
                    Ok(_) | Err(_) => Alive::Dead,
                }
            }
        }
    }
}

/// A stream's layers that work on its bytes, bottom first. Empty, it
/// allocates nothing; it is held by one pointer, as every transfer's
/// state holds a connection's inline and the first layer, TLS's, is
/// rare.
#[derive(Debug, Default)]
pub(crate) struct LayerStack {
    #[expect(
        clippy::box_collection,
        reason = "one pointer in every transfer's state"
    )]
    layers: Option<Box<Vec<Box<dyn Layer>>>>,
}

impl LayerStack {
    /// The stack over `socket`, from its top.
    pub(crate) fn over<'a>(&'a mut self, socket: &'a dyn Socket) -> Below<'a> {
        Below {
            layers: self
                .layers
                .as_deref_mut()
                .map_or(&mut [], Vec::as_mut_slice),
            socket,
        }
    }

    /// Put `layer` on top.
    #[cfg_attr(
        not(test),
        expect(dead_code, reason = "TLS pushes its layer, step 43; tests push theirs")
    )]
    pub(crate) fn push(&mut self, layer: Box<dyn Layer>) -> Result<(), OutOfMemory> {
        let layers = match &mut self.layers {
            Some(layers) => layers,
            None => self.layers.insert(try_box(Vec::new())?),
        };
        layers.try_push(layer)
    }

    /// What the transfer is to wait for, given what it wants, each layer
    /// adjusting it from the top down (`Curl_conn_cf_adjust_pollset`).
    pub(crate) fn adjust_pollset(&self, wanted: Events) -> Events {
        self.layers
            .iter()
            .flat_map(|l| l.iter())
            .rev()
            .fold(wanted, |wanted, layer| layer.adjust_pollset(wanted))
    }
}

/// Layers for the tests of what the stack asks of its layers.
#[cfg(test)]
pub(crate) mod testing {
    use super::*;

    /// Passes the bytes, and asks to write whenever the transfer waits,
    /// as TLS does with bytes to flush.
    #[derive(Debug)]
    pub(crate) struct WantsOut;

    pub(crate) fn wants_out() -> Box<dyn Layer> {
        try_box(WantsOut).unwrap()
    }

    impl Layer for WantsOut {
        fn recv(
            &mut self,
            cx: &mut dyn LayerCx,
            below: Below<'_>,
            buf: &mut [u8],
        ) -> io::Result<Recv> {
            below.recv(cx, buf)
        }

        fn send(
            &mut self,
            cx: &mut dyn LayerCx,
            below: Below<'_>,
            bytes: &[u8],
        ) -> io::Result<Sent> {
            below.send(cx, bytes)
        }

        fn adjust_pollset(&self, wanted: Events) -> Events {
            wanted | Events::OUT
        }
    }

    /// Makes the letters it passes upper case, both ways.
    #[derive(Debug)]
    pub(crate) struct Upper;

    pub(crate) fn upper() -> Box<dyn Layer> {
        try_box(Upper).unwrap()
    }

    impl Layer for Upper {
        fn recv(
            &mut self,
            cx: &mut dyn LayerCx,
            below: Below<'_>,
            buf: &mut [u8],
        ) -> io::Result<Recv> {
            let got = below.recv(cx, buf)?;
            if let Recv::Data(n) = got {
                buf[..n.get()].make_ascii_uppercase();
            }
            Ok(got)
        }

        fn send(
            &mut self,
            cx: &mut dyn LayerCx,
            below: Below<'_>,
            bytes: &[u8],
        ) -> io::Result<Sent> {
            let mut upper = [0u8; 4096];
            let n = bytes.len().min(upper.len());
            upper[..n].copy_from_slice(&bytes[..n]);
            upper[..n].make_ascii_uppercase();
            below.send(cx, &upper[..n])
        }
    }

    /// Reads what is below, and gives it only at the next read: the read
    /// that took it would block, as TLS's may with a record half read.
    #[derive(Debug, Default)]
    pub(crate) struct Holdback {
        held: Vec<u8>,
    }

    pub(crate) fn holdback() -> Box<dyn Layer> {
        try_box(Holdback::default()).unwrap()
    }

    impl Layer for Holdback {
        fn recv(
            &mut self,
            cx: &mut dyn LayerCx,
            below: Below<'_>,
            buf: &mut [u8],
        ) -> io::Result<Recv> {
            if let Some(n) = std::num::NonZeroUsize::new(self.held.len().min(buf.len())) {
                buf[..n.get()].copy_from_slice(&self.held[..n.get()]);
                self.held.drain(..n.get());
                return Ok(Recv::Data(n));
            }
            let got = below.recv(cx, buf)?;
            match got {
                Recv::Data(n) => {
                    self.held.try_extend_from_slice(&buf[..n.get()]).unwrap();
                    Ok(Recv::WouldBlock)
                }
                Recv::Eof | Recv::WouldBlock => Ok(got),
            }
        }

        fn send(
            &mut self,
            cx: &mut dyn LayerCx,
            below: Below<'_>,
            bytes: &[u8],
        ) -> io::Result<Sent> {
            below.send(cx, bytes)
        }

        fn data_pending(&self, below: Below<'_>) -> bool {
            !self.held.is_empty() || below.data_pending()
        }
    }

    /// Passes the bytes, and says the connection is dead.
    #[derive(Debug)]
    pub(crate) struct Dying;

    pub(crate) fn dying() -> Box<dyn Layer> {
        try_box(Dying).unwrap()
    }

    impl Layer for Dying {
        fn recv(
            &mut self,
            cx: &mut dyn LayerCx,
            below: Below<'_>,
            buf: &mut [u8],
        ) -> io::Result<Recv> {
            below.recv(cx, buf)
        }

        fn send(
            &mut self,
            cx: &mut dyn LayerCx,
            below: Below<'_>,
            bytes: &[u8],
        ) -> io::Result<Sent> {
            below.send(cx, bytes)
        }

        fn is_alive(&mut self, _: &mut dyn LayerCx, _: Below<'_>) -> Alive {
            Alive::Dead
        }
    }
}
