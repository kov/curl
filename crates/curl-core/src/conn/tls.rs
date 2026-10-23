//! The layer a TLS session makes of a connection (C's SSL filter,
//! `lib/vtls/vtls.c`): it hands each call to the session with the layers
//! below, the caller's buffer and length as they are, so the session's
//! own reads are the sizes below it.

use std::fmt;
use std::io;

use curl_alloc::{OutOfMemory, try_box};

use super::io::{Events, Recv, Sent};
use super::layer::{Below, Handshake, Layer, LayerCx};
use crate::components::Component;
use crate::error::ErrorKind;
use crate::tls::{TlsIo, TlsSession, TlsWait};

pub(crate) struct TlsLayer {
    session: Box<dyn TlsSession>,
    /// What the connection received before the layer was put on it,
    /// after a proxy's answer: the peer's first bytes, read before any
    /// from below.
    early: Vec<u8>,
}

impl TlsLayer {
    /// The layer over a connection that received `early` and has not
    /// used it.
    pub(crate) fn boxed(
        session: Box<dyn TlsSession>,
        early: Vec<u8>,
    ) -> Result<Box<dyn Layer>, OutOfMemory> {
        Ok(try_box(TlsLayer { session, early })?)
    }

    /// The session, and what it reaches for one call.
    fn parts<'a>(
        &'a mut self,
        cx: &'a mut dyn LayerCx,
        below: Below<'a>,
    ) -> (&'a mut dyn TlsSession, TlsIo<'a>) {
        let TlsLayer { session, early } = self;
        (&mut **session, TlsIo::new(below, cx, early, Component::Ssl))
    }
}

impl fmt::Debug for TlsLayer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TlsLayer")
            .field("early", &self.early.len())
            .finish_non_exhaustive()
    }
}

impl Layer for TlsLayer {
    fn connect(&mut self, cx: &mut dyn LayerCx, below: Below<'_>) -> Result<Handshake, ErrorKind> {
        let (session, mut io) = self.parts(cx, below);
        session.handshake(&mut io)
    }

    fn recv(&mut self, cx: &mut dyn LayerCx, below: Below<'_>, buf: &mut [u8]) -> io::Result<Recv> {
        let (session, mut io) = self.parts(cx, below);
        session.recv(&mut io, buf)
    }

    fn send(&mut self, cx: &mut dyn LayerCx, below: Below<'_>, bytes: &[u8]) -> io::Result<Sent> {
        let (session, mut io) = self.parts(cx, below);
        session.send(&mut io, bytes)
    }

    /// What the session waits for replaces what the transfer wants
    /// (`Curl_ssl_adjust_pollset`'s `set_out_only` and `set_in_only`).
    fn adjust_pollset(&self, wanted: Events) -> Events {
        match self.session.waits() {
            TlsWait::Nothing => wanted,
            TlsWait::Recv => Events::IN,
            TlsWait::Send => Events::OUT,
        }
    }

    fn data_pending(&self, below: Below<'_>) -> bool {
        !self.early.is_empty() || self.session.pending() || below.data_pending()
    }

    fn shutdown(&mut self, cx: &mut dyn LayerCx, below: Below<'_>) -> Result<Handshake, ErrorKind> {
        let (session, mut io) = self.parts(cx, below);
        session.shutdown(&mut io)
    }
}
