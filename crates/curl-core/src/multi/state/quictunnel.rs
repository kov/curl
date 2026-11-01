//! The origin's QUIC connection through a CONNECT-UDP tunnel
//! (`cf_setup_add_origin_filters` for QUIC behind an HTTP proxy): the
//! capsule layer goes on the tunnel's stream, taking what the proxy sent
//! after its answer, and the QUIC connection's handshake is made over
//! it, each datagram a capsule. Once made, the connection is the
//! origin's HTTP/3 session's.

use curl_alloc::{OutOfMemory, try_box};

use super::{Failure, Handshake, Lent, SetupMut, StepCx, Wake};
use crate::conn::Handshook;
use crate::conn::capsule::CapsuleLayer;
use crate::conn::quic::{Over, Quic};
use crate::error::ErrorKind;
use crate::multi::Host;
use crate::multi::cx::DriveCx;

/// The tunnel is up: the capsule layer and the origin's QUIC connection
/// go over it.
pub(super) fn start<H: Host>(
    s: &mut SetupMut<'_>,
    _: &mut Lent<'_>,
    cx: &mut StepCx<'_, H>,
) -> Result<Wake, Failure> {
    let stream = s.machine.dialed().stream();
    let pushed = stream.push_over_received(|received| {
        try_box(CapsuleLayer::holding(received)).map(|l| l as Box<dyn crate::conn::layer::Layer>)
    });
    if let Err(OutOfMemory) = pushed {
        return Err(Failure::Transfer(ErrorKind::OutOfMemory));
    }
    let made = s.machine.tunnel_quic(&mut DriveCx {
        step: cx,
        kept: None,
        deadlines: None,
    });
    let mut quic = match made {
        Ok(quic) => quic,
        Err(kind) => return Err(Failure::Attempt(kind)),
    };
    // Its first flight goes over the tunnel; sending early data, it is
    // connected at once (`Curl_cf_ngtcp2_cmn_connect` with no connection
    // yet, `cf->connected` set by `cf_ngtcp2_on_session_reuse`).
    let traced = Some(s.machine.dialing().socket_component());
    let stream = s.machine.dialed().stream();
    let mut over = Over {
        cx,
        on: stream.below(traced),
    };
    match quic.start(&mut over) {
        Ok(false) => {}
        Ok(true) => {
            made_over(s, quic);
            return Ok(Wake::Again);
        }
        Err(kind) => return Err(Failure::Attempt(kind)),
    }
    match try_box(Handshake::Quic(quic)) {
        Ok(h) => {
            s.handshake = Some(h);
            Ok(Wake::Idle)
        }
        Err(OutOfMemory) => Err(Failure::Transfer(ErrorKind::OutOfMemory)),
    }
}

/// The origin's QUIC connection over the tunnel is made: the dialed
/// connection's from now on.
fn made_over(s: &mut SetupMut<'_>, quic: Box<Quic>) {
    let dialed = s.machine.dialed();
    dialed.put_quic(quic);
    dialed.mark_made(Handshook::Quic);
}

/// Move the handshake on, its datagrams through the tunnel's layers.
pub(super) fn step<H: Host>(
    s: &mut SetupMut<'_>,
    _: &mut Lent<'_>,
    cx: &mut StepCx<'_, H>,
) -> Result<Wake, Failure> {
    let Some(Handshake::Quic(quic)) = s.handshake.as_deref_mut() else {
        unreachable!("the origin's QUIC handshake is under way");
    };
    // The tunnel's bytes are the socket's, traced as C's socket filter
    // traces them.
    let traced = Some(s.machine.dialing().socket_component());
    let stream = s.machine.dialed().stream();
    let mut over = Over {
        cx,
        on: stream.below(traced),
    };
    match quic.connect(&mut over) {
        Ok(false) => Ok(Wake::Idle),
        Ok(true) => {
            let Some(Handshake::Quic(quic)) = s.handshake.take().map(|h| *h) else {
                unreachable!("the origin's QUIC handshake was under way");
            };
            made_over(s, quic);
            Ok(Wake::Again)
        }
        Err(kind) => Err(Failure::Attempt(kind)),
    }
}
