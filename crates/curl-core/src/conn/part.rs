//! What every piece of a connection answers of its life, whatever it does
//! with the bytes (C's `Curl_cftype`, less its `send` and `recv`): its
//! setup, what it waits on, what it holds, whether the connection still
//! seems usable, its goodbye, and the questions asked of the connection.
//!
//! The pieces are the layers over a stream (`Layer`, which adds the bytes
//! both ways) and the session that multiplexes streams over them
//! (`conn::mux`). Each is asked given what lies below it, `B`: the layers
//! under a layer, down to the socket, or the stream under a session. The
//! connection asks its pieces from the top: the session, then the layers.

use super::io::Events;
use super::layer::{Alive, Handshake, LayerAnswer, LayerCx, LayerQuery};
use crate::components::Component;
use crate::error::ErrorKind;

/// What lies below a piece of a connection, which a piece that keeps the
/// defaults passes the question to.
pub(crate) trait Lower {
    /// Bytes wait below where a poll of the socket cannot see them.
    fn data_pending(self) -> bool;

    /// Whether the connection seems usable, as what is below says.
    fn alive(self, cx: &mut dyn LayerCx) -> Alive;
}

/// A piece of a connection, over `B`. A piece that keeps a default has
/// nothing of its own to say there, and passes the question below.
pub(crate) trait Part<B: Lower> {
    /// Move its handshake on: TLS's, which may take more than one pass.
    /// A piece that has none is connected at once.
    fn connect(&mut self, _cx: &mut dyn LayerCx, _below: B) -> Result<Handshake, ErrorKind> {
        Ok(Handshake::Done)
    }

    /// What the transfer is to wait for on the socket, given what it
    /// wants (TLS wants to write while it reads).
    fn adjust_pollset(&self, wanted: Events) -> Events {
        wanted
    }

    /// Whether it, or what is below, holds bytes a poll of the socket
    /// cannot see.
    fn data_pending(&self, below: B) -> bool {
        below.data_pending()
    }

    /// Whether the connection seems usable, asking below.
    fn is_alive(&mut self, cx: &mut dyn LayerCx, below: B) -> Alive {
        below.alive(cx)
    }

    /// Move its goodbye on: say it to the peer, which may take more than
    /// one pass (TLS's close_notify), or a frame that goes as it can
    /// (HTTP/2's GOAWAY).
    fn shutdown(&mut self, _cx: &mut dyn LayerCx, _below: B) -> Result<Handshake, ErrorKind> {
        Ok(Handshake::Done)
    }

    /// Send the peer what keeps the connection alive, if it has such a
    /// thing (`keep_alive`): HTTP/2's PING. No layer under a session
    /// has, nor a session over QUIC, whose own timer keeps it alive: the
    /// default sends nothing, and is not passed below.
    fn keep_alive(&mut self, _cx: &mut dyn LayerCx, _below: B) -> Result<(), ErrorKind> {
        Ok(())
    }

    /// Answer a question asked of the connection, if it can; the pieces
    /// below are asked if it does not.
    fn query(&self, _q: LayerQuery) -> Option<LayerAnswer> {
        None
    }

    /// The filter it is, that its lines are traced as; none for a piece
    /// C has no filter for.
    fn filter(&self) -> Option<Component> {
        None
    }

    /// What it puts in a pollset that C's filter says as it does
    /// (`Curl_ssl_adjust_pollset`'s line); nothing, for most.
    fn pollset_said(&self) -> Option<Events> {
        None
    }
}
