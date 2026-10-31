//! The setup of a connection a protocol makes beside the transfer's own,
//! FTP's data connection (C's `SECONDARYSOCKET`): once its first hop is
//! dialed, the handshakes over it, a SOCKS proxy's, an HTTPS proxy's TLS,
//! an HTTP proxy's tunnel and the PROXY protocol's line, are made by the
//! drivers the transfer's connection is set up by, over what the
//! protocol's request lends them, as C's ftp.c connects the second
//! socket's filters from its own phases.

use crate::conn::ConnectMachine;
use crate::conn::chain::SetupPoint;
use crate::conn::io::{Events, Socket};
use crate::error::ErrorKind;
use crate::multi::Host;
use crate::proto::http::negotiate::Negotiate;

use super::{
    ConnRank, Failure, Handshake, Lent, SetupLend, SetupMut, StepCx, Wake, handshake_due,
    start_handshake, step_handshake,
};

/// What is under way over a side connection's first hop: its handshake,
/// and the Negotiate context with the proxy its tunnel goes through.
#[derive(Debug, Default)]
pub(crate) struct SideSetup {
    handshake: Option<Box<Handshake>>,
    negotiate: Option<Box<Negotiate>>,
}

/// How far a side setup's handshakes came.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Shaken {
    /// One waits on the socket.
    Waiting,
    /// They are all made: the connection is up.
    Up,
    /// The proxy closed the connection as it asked for credentials: its
    /// first hop is dialed again, before the next `CONNECT`.
    Redialed,
}

impl SideSetup {
    /// Move the handshakes over `machine`, dialed, on as far as they go
    /// now, in cf-setup.c's order, for `request`. A failure is the
    /// transfer's: the setup is not raced.
    pub(crate) fn shake<H: Host>(
        &mut self,
        machine: &mut ConnectMachine,
        request: &mut dyn SetupLend,
        cx: &mut StepCx<'_, H>,
    ) -> Result<Shaken, ErrorKind> {
        let route = machine.route().clone();
        loop {
            let SetupPoint::Dialed(made) = machine.reached() else {
                return Ok(Shaken::Redialed);
            };
            let mut s = SetupMut {
                machine: &mut *machine,
                handshake: &mut self.handshake,
            };
            let mut t = Lent {
                route: &route,
                request: &mut *request,
                negotiate: &mut self.negotiate,
                rank: ConnRank::Second,
            };
            let shook = if s.handshake.is_some() {
                step_handshake(&mut s, &mut t, cx)
            } else {
                match handshake_due(&route, s.machine, made) {
                    Some(due) => start_handshake(&mut s, &mut t, cx, due),
                    None => return Ok(Shaken::Up),
                }
            };
            match shook {
                Ok(Wake::Again) => {}
                Ok(Wake::Idle) => return Ok(Shaken::Waiting),
                Err(Failure::Attempt(kind) | Failure::Transfer(kind)) => return Err(kind),
            }
        }
    }

    /// The sockets of the setup over `machine`, and what each waits for:
    /// a handshake's, what it sends or reads and to read too, as the
    /// transfer's do; with none under way, the attempts' racing.
    pub(crate) fn pollset<'a>(
        &'a self,
        machine: &'a ConnectMachine,
    ) -> impl Iterator<Item = (&'a dyn Socket, Events)> {
        let shaking = self
            .handshake
            .as_deref()
            .map(|h| h.interest(machine) | Events::IN);
        let shaken = shaking
            .into_iter()
            .flat_map(move |events| machine.sockets().map(move |s| (s, events)));
        let racing = machine.racing_wants().filter(move |_| shaking.is_none());
        shaken.chain(racing)
    }
}
