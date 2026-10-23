//! The origin's TLS handshake, the last of a connection's setup
//! (`cf_setup_connect`'s SSL stage): the handle's TLS library makes a
//! session for the origin, whose layer goes on top of the connection's
//! stream and is connected there; the request's bytes go through it
//! after.

use curl_alloc::{OutOfMemory, try_box};

use super::{Connecting, Handshake, StepCx, TransferState, Wake};
use crate::conn::Made;
use crate::conn::tls::TlsLayer;
use crate::error::ErrorKind;
use crate::multi::Host;
use crate::tls::{Handshake as Shake, TlsPeer};

/// The handshakes before it are made: the session is made and its layer
/// put on the stream, taking the bytes the stream received and did not
/// use, which follow a proxy's answer.
pub(super) fn start<H: Host>(mut c: Connecting, cx: &mut StepCx<'_, H>) -> (TransferState, Wake) {
    let backend = cx
        .easy()
        .libraries()
        .tls
        .expect("a route has TLS only with a TLS library");
    let identity = c.route.tls.as_deref().expect("a TLS route");
    let session = match backend.session(identity, &TlsPeer::of(&c.route.origin)) {
        Ok(session) => session,
        Err(kind) => return (TransferState::Connecting(c).fail(kind), Wake::Again),
    };
    let stream = c.lease.dialed().stream();
    let pushed = stream
        .push_over_received(|early| TlsLayer::boxed(session, early))
        .and_then(|()| try_box(Handshake::Tls));
    match pushed {
        Ok(h) => {
            c.handshake = Some(h);
            (TransferState::Connecting(c), Wake::Again)
        }
        Err(OutOfMemory) => (
            TransferState::Connecting(c).fail(ErrorKind::OutOfMemory),
            Wake::Again,
        ),
    }
}

/// Move the handshake on, as far as the socket lets it.
pub(super) fn step<H: Host>(mut c: Connecting, cx: &mut StepCx<'_, H>) -> (TransferState, Wake) {
    match c.lease.dialed().stream().connect(cx) {
        Ok(Shake::Done) => {
            c.lease.dialed().mark_made(Made::TLS);
            c.handshake = None;
            (TransferState::Connecting(c), Wake::Again)
        }
        Ok(Shake::Waiting) => (TransferState::Connecting(c), Wake::Idle),
        Err(kind) => (TransferState::Connecting(c).fail(kind), Wake::Again),
    }
}
