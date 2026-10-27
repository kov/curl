//! The origin's QUIC connection through a CONNECT-UDP tunnel
//! (`cf_setup_add_origin_filters` for QUIC behind an HTTP proxy): the
//! capsule layer goes on the tunnel's stream, taking what the proxy sent
//! after its answer, and the QUIC connection's handshake is made over
//! it, each datagram a capsule. Once made, the connection is the
//! origin's HTTP/3 session's.

use curl_alloc::{OutOfMemory, try_box};

use super::{Connecting, Handshake, StepCx, TransferState, Wake};
use crate::conn::Made;
use crate::conn::capsule::CapsuleLayer;
use crate::conn::quic::{Over, Path};
use crate::error::ErrorKind;
use crate::multi::Host;
use crate::multi::cx::DriveCx;

/// The tunnel is up: the capsule layer and the origin's QUIC connection
/// go over it.
pub(super) fn start<H: Host>(mut c: Connecting, cx: &mut StepCx<'_, H>) -> (TransferState, Wake) {
    let stream = c.lease.dialed().stream();
    let pushed = stream.push_over_received(|received| {
        try_box(CapsuleLayer::holding(received)).map(|l| l as Box<dyn crate::conn::layer::Layer>)
    });
    if let Err(OutOfMemory) = pushed {
        return (
            TransferState::Connecting(c).fail(ErrorKind::OutOfMemory),
            Wake::Again,
        );
    }
    let made = c.lease.tunnel_quic(&mut DriveCx {
        step: cx,
        kept: None,
        deadlines: None,
    });
    let quic = match made {
        Ok(quic) => quic,
        Err(kind) => return super::attempt_failed(c, cx, kind),
    };
    match try_box(Handshake::Quic(quic)) {
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

/// Move the handshake on, its datagrams through the tunnel's layers.
pub(super) fn step<H: Host>(mut c: Connecting, cx: &mut StepCx<'_, H>) -> (TransferState, Wake) {
    let Some(Handshake::Quic(quic)) = c.handshake.as_deref_mut() else {
        unreachable!("the origin's QUIC handshake is under way");
    };
    // The tunnel's bytes are the socket's, traced as C's socket filter
    // traces them.
    let traced = Some(c.route.socket_component());
    let stream = c.lease.dialed().stream();
    let mut over = Over {
        cx,
        path: Path::Layers(stream.below(traced)),
    };
    match quic.connect(&mut over) {
        Ok(false) => (TransferState::Connecting(c), Wake::Idle),
        Ok(true) => {
            let Some(Handshake::Quic(quic)) = c.handshake.take().map(|h| *h) else {
                unreachable!("the origin's QUIC handshake was under way");
            };
            let dialed = c.lease.dialed();
            dialed.put_quic(quic);
            dialed.mark_made(Made::QUIC);
            (TransferState::Connecting(c), Wake::Again)
        }
        Err(kind) => super::attempt_failed(c, cx, kind),
    }
}
