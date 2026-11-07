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
    Chain, ConnRank, Failure, Head, Lent, SetupLend, SetupMut, StepCx, Wake, connect_ended_at,
    enter_chain, handshake_due, mstate, names, start_handshake, step_handshake,
};
use crate::components::Component;
use crate::conn::NetRoute;
use crate::trace;

/// What a side connection's setup keeps beside its machine: the Negotiate
/// context with the proxy its tunnel goes through.
#[derive(Debug, Default)]
pub(crate) struct SideSetup {
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

/// The second chain is set up over `route` (`Curl_conn_setup`), said as
/// the transfer's own is, in place of the one before, whose DNS filters
/// let go of what they hold (`Curl_conn_cf_discard_all`).
pub(crate) fn chain_set_up<H: Host>(cx: &mut StepCx<'_, H>, route: &NetRoute) {
    names::filters_done(cx, Some(ConnRank::Second));
    cx.as_second(|cx| {
        trace::of(cx, Component::Setup, format_args!("added"));
        names::chain_set_up(cx, route, false, false);
    });
}

/// A call of the chain's connect (`Curl_conn_connect`) reaches the name's
/// filter first, which starts (`cf_dns_start`).
pub(crate) fn chain_started<H: Host>(cx: &mut StepCx<'_, H>, machine: &ConnectMachine) {
    if machine.unasked() {
        names::started(cx, machine.route());
    }
}

/// The call ends with the connect still under way, said by `top`, the
/// filter at the chain's top.
pub(crate) fn call_waits<H: Host>(cx: &mut StepCx<'_, H>, top: Component) {
    connect_ended_at(cx, top, Ok(false));
}

/// The call ends in `kind`: said by the name's filter, and the chain that
/// failed named (`Curl_conn_connect`).
pub(crate) fn call_failed<H: Host>(cx: &mut StepCx<'_, H>, kind: ErrorKind, chain: Chain) {
    let top = chain.top().unwrap_or(Component::DnsFilter);
    connect_ended_at(cx, top, Err(kind));
    mstate::trace(cx, format_args!("failed to connect {chain}"));
}

/// The call ends with all of `connected` connected.
pub(crate) fn call_connected<H: Host>(cx: &mut StepCx<'_, H>, connected: Chain) {
    // Its SOCKS proxy's target's filter, if it has one, below the first
    // hop's; never the record's. An accepted connection has none.
    if connected.dns_filters() > 0 {
        let target = connected.dns_filters() > 1;
        names::connected(cx, ConnRank::Second, target, false, false, |_, _| {});
    }
    let top = connected.top().unwrap_or(Component::DnsFilter);
    connect_ended_at(cx, top, Ok(true));
}

/// The chain being set up over its first hop adds its TLS, as `chain`
/// shows it: said as its setup filter says it, if it has one.
pub(crate) fn tls_added<H: Host>(cx: &mut StepCx<'_, H>, chain: Chain) {
    if chain.dns_filters() > 0 {
        trace::of(
            cx,
            Component::Setup,
            format_args!("added SSL filter for origin"),
        );
        mstate::trace(cx, format_args!("cf_setup_connect {chain}"));
    }
}

/// SETUP's connect is entered as the chain's TLS is made: `chain`.
pub(crate) fn entered_tls<H: Host>(cx: &mut StepCx<'_, H>, chain: Chain) {
    if chain.dns_filters() > 0 {
        mstate::trace(cx, format_args!("cf_setup_connect {chain}"));
    }
}

/// The chain `connected` is connected: its setup filters go
/// (`Curl_conn_remove_setup_filters`).
pub(crate) fn setup_filters_go<H: Host>(cx: &mut StepCx<'_, H>, connected: Chain) {
    mstate::trace(cx, format_args!("connected {connected}"));
    // Its SOCKS proxy's target's filter, if it has one, below the first
    // hop's; never the record's; none for a connection accepted from the
    // server.
    let filters = connected.dns_filters();
    let dns = names::filters(ConnRank::Second, filters > 1, false, false).take(filters);
    names::setup_filters_go(cx, &connected, ConnRank::Second, dns, |_, _| {});
    let reduced = connected.reduced();
    mstate::trace(cx, format_args!("reduced to {reduced}"));
}

impl SideSetup {
    /// SETUP's connect is entered (`cf_setup_connect`): the chain as it
    /// goes on to, said as the transfer's own is.
    pub(crate) fn enter<H: Host>(
        &self,
        machine: &ConnectMachine,
        cx: &mut StepCx<'_, H>,
        entered: &mut bool,
    ) -> Chain {
        let under_way = machine.handshake.as_deref().map(super::Handshake::filter);
        let plan = machine.route().clone();
        enter_chain(
            machine,
            &plan,
            Head::default(),
            under_way,
            cx,
            entered,
            None,
        )
    }

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
            let mut s = SetupMut::of(&mut *machine);
            let mut t = Lent {
                route: &route,
                request: &mut *request,
                negotiate: &mut self.negotiate,
                rank: ConnRank::Second,
                // A second connection's protocol is not HTTP's, and asks
                // for no record.
                record: super::https::RecordNow::Known(None),
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
        let shaking = machine
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
