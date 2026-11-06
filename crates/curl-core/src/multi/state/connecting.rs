//! A transfer's side of setting up a connection: the attempts, their
//! race and handshakes, and how the setup ends.

use super::*;

/// Who is asked for an origin's HTTPS record.
#[derive(Debug)]
pub(crate) enum RecordLookup {
    Doh(crate::multi::doh::Lookup),
    Library(Box<dyn crate::conn::io::DnsResolve>),
}

/// A request whose connection is being set up.
#[derive(Debug)]
pub(crate) struct Connecting {
    pub(super) lease: ConnLease,
    pub(super) proto: ProtoState,
    /// The plan's route: the host and port the request is for, the peer
    /// connected to in their place and the proxy on the way, as the
    /// failure names them.
    pub(super) route: NetRoute,
    /// The HTTPS connect filter heading the setup, if it has one.
    pub(super) https: Option<https::HttpsConnect>,
    /// The origin's HTTPS record, once known that it has one.
    pub(super) record: Option<curl_alloc::TryArc<crate::doh::HttpsRecord>>,
    /// Its resolve over DoH, while it goes on: gone with the setup.
    pub(super) record_lookup: Option<RecordLookup>,
    /// The race of an HTTP/3 attempt against one over TCP, once its first
    /// started: what the second is made from, and the QUIC attempt out
    /// of the lease while both run.
    pub(super) race: Option<Box<Race>>,
    /// HTTP Negotiate with the proxy a tunnel goes through, before the
    /// connection it belongs to is up: kept across a redial, as C keeps it
    /// on the connection whose filters it makes again, and handed to the
    /// connection as it comes up.
    pub(super) negotiate: Option<Box<crate::proto::http::negotiate::Negotiate>>,
}

/// A machine and its handshake apart, for as long as a handshake's driver
/// works on the two together: the handshake goes back to the machine as
/// this goes.
pub(super) struct SetupMut<'a> {
    pub(super) machine: &'a mut ConnectMachine,
    pub(super) handshake: Option<Box<Handshake>>,
}

impl<'a> SetupMut<'a> {
    pub(super) fn of(machine: &'a mut ConnectMachine) -> Self {
        let handshake = machine.handshake.take();
        SetupMut { machine, handshake }
    }
}

impl Drop for SetupMut<'_> {
    fn drop(&mut self) {
        self.machine.handshake = self.handshake.take();
    }
}

/// What the transfer lends a handshake's driver: the route it plans, what
/// its request lends the setup, the connection's Negotiate with its proxy,
/// and which of the transfer's connections it is.
pub(super) struct Lent<'a> {
    pub(super) route: &'a NetRoute,
    pub(super) request: &'a mut dyn SetupLend,
    pub(super) negotiate: &'a mut Option<Box<crate::proto::http::negotiate::Negotiate>>,
    pub(super) rank: ConnRank,
}

/// Which of a transfer's connections a setup makes: the one it is made
/// over, or the second a protocol makes beside it, FTP's data connection
/// (C's `FIRSTSOCKET` and `SECONDARYSOCKET`), which a few of the lines
/// said of its setup name.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ConnRank {
    First,
    Second,
}

impl ConnRank {
    /// How C's lines name it: the second as `2nd `, the first not at all.
    pub(crate) fn ordinal(self) -> &'static str {
        match self {
            ConnRank::First => "",
            ConnRank::Second => "2nd ",
        }
    }
}

/// What a request lends the handshakes that set its connection up, which
/// every request answers itself: whether the application's credentials
/// may go to the origin, which a tunnel's `CONNECT` takes the custom
/// headers by; the pipeline the proxy's answer to it goes through, as
/// the request's own headers do; and, for HTTP's alone, the versions it
/// may speak, which TLS offers by ALPN and the HTTPS connect filter
/// chooses its attempts by.
pub(crate) trait SetupLend {
    /// Whether credentials may go to the request's origin.
    fn trusted(&self) -> Option<crate::auth::creds::Trusted>;

    /// The pipeline the answer to a tunnel's `CONNECT` is delivered to.
    fn pipeline(&mut self) -> &mut Pipeline;

    /// What it may speak as HTTP; none for a protocol that is not HTTP.
    fn negotiation(&self) -> Option<crate::proto::http::Negotiation>;

    /// The same, to change.
    fn negotiation_mut(&mut self) -> Option<&mut crate::proto::http::Negotiation>;
}

/// How a handshake failed: its attempt alone, which a race outlives, or
/// the transfer, as running out of memory does.
#[derive(Clone, Copy, Debug)]
pub(super) enum Failure {
    Attempt(ErrorKind),
    Transfer(ErrorKind),
}

impl Failure {
    /// A handshake's failure with `kind`: its attempt's, as C's HTTPS
    /// connect filter takes a baller's result, but running out of memory,
    /// which fails the transfer.
    pub(super) fn of(kind: ErrorKind) -> Failure {
        match kind {
            ErrorKind::OutOfMemory => Failure::Transfer(kind),
            kind => Failure::Attempt(kind),
        }
    }
}

impl Connecting {
    /// Attempt `a`'s setup and what the transfer lends it, borrowed
    /// apart.
    fn shaking(&mut self, a: Attempt) -> (SetupMut<'_>, Lent<'_>) {
        let Connecting {
            lease,
            proto,
            route,
            race,
            negotiate,
            ..
        } = self;
        let machine = match (a, race.as_deref_mut()) {
            (Attempt::Second, Some(race)) => race.second.running_mut().expect("the second runs"),
            (Attempt::Second, None) => panic!("a second runs in a race"),
            (Attempt::First, _) => lease.setting_up(),
        };
        (
            SetupMut::of(machine),
            Lent {
                route,
                request: proto,
                negotiate,
                rank: ConnRank::First,
            },
        )
    }

    /// The transfer goes on as a driver of attempt `a`'s handshake says.
    fn shook<H: Host>(
        self,
        a: Attempt,
        shook: Result<Wake, Failure>,
        cx: &mut StepCx<'_, H>,
    ) -> (TransferState, Wake) {
        match shook {
            Ok(wake) => (TransferState::Connecting(self), wake),
            Err(Failure::Transfer(kind)) => {
                (TransferState::Connecting(self).fail(kind), Wake::Again)
            }
            Err(Failure::Attempt(kind)) => attempt_failed(self, cx, a, kind),
        }
    }
}

/// The race of an HTTP/3 attempt against an HTTP/2-or-1 one over TCP, as
/// C's HTTPS connect filter runs its two ballers, either first. The first
/// is the lease's setup throughout; the second runs beside it. One of
/// them leads: the transfer reports, traces the chain of and makes the
/// handshakes of the lead's setup. Once one wins, its connection is the
/// lease's and the other goes with the filter; a race given up goes with
/// the request, both its attempts closed as the lease is given back.
#[derive(Debug)]
pub(super) struct Race {
    /// The addresses the first resolved, or the Unix socket it connects
    /// to, which the second races.
    pub(super) answer: Addresses,
    /// The connection's makings, which the second is made with.
    makings: (Closer, ConnSettings, Instant),
    /// The second attempt.
    pub(super) second: RaceSecond,
    /// Which attempt leads: a second over TCP once it starts, else the
    /// first.
    pub(super) lead: Attempt,
    /// When the first started (`ctx->started`), which the second's
    /// timeouts count from.
    pub(super) at: Instant,
    /// The first failed, with this (`ballers[0].result`), which is the
    /// setup's if the second fails too.
    pub(super) first_failed: Option<ErrorKind>,
    /// The first attempt, if it failed once dialed: its connection kept
    /// until the race ends, as C keeps a failed baller's chain. The
    /// lease holds it failed, with no machine.
    pub(super) failed: Option<ConnectMachine>,
    /// The first's peer answered, found once asked (`reply_ms`), which is
    /// not asked again.
    pub(super) replied: bool,
}

/// Where a race's second attempt stands.
#[derive(Debug)]
pub(super) enum RaceSecond {
    /// It has not started.
    Unstarted,
    /// It runs beside the first.
    Running(ConnectMachine),
    /// It failed once dialed: its connection is kept until the race ends,
    /// as C keeps a failed baller's chain.
    Kept(ConnectMachine),
    /// It failed before it dialed, or it won or lost and its machine went.
    Gone,
}

impl RaceSecond {
    pub(super) fn running(&self) -> Option<&ConnectMachine> {
        match self {
            RaceSecond::Running(m) => Some(m),
            RaceSecond::Unstarted | RaceSecond::Kept(_) | RaceSecond::Gone => None,
        }
    }

    fn running_mut(&mut self) -> Option<&mut ConnectMachine> {
        match self {
            RaceSecond::Running(m) => Some(m),
            RaceSecond::Unstarted | RaceSecond::Kept(_) | RaceSecond::Gone => None,
        }
    }

    /// The machine, if it runs, the attempt gone.
    fn take_running(&mut self) -> Option<ConnectMachine> {
        if !matches!(self, RaceSecond::Running(_)) {
            return None;
        }
        match std::mem::replace(self, RaceSecond::Gone) {
            RaceSecond::Running(m) => Some(m),
            _ => unreachable!("it was running"),
        }
    }

    /// Its machine, running or kept, if it has one.
    pub(super) fn into_machine(self) -> Option<ConnectMachine> {
        match self {
            RaceSecond::Running(m) | RaceSecond::Kept(m) => Some(m),
            RaceSecond::Unstarted | RaceSecond::Gone => None,
        }
    }

    /// Its machine, if it failed once dialed.
    pub(super) fn kept(&self) -> Option<&ConnectMachine> {
        match self {
            RaceSecond::Kept(m) => Some(m),
            RaceSecond::Unstarted | RaceSecond::Running(_) | RaceSecond::Gone => None,
        }
    }
}

/// One of a race's attempts: the first, the lease's, or the second.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Attempt {
    First,
    Second,
}

impl Attempt {
    /// The attempt beside it.
    pub(super) fn other(self) -> Attempt {
        match self {
            Attempt::First => Attempt::Second,
            Attempt::Second => Attempt::First,
        }
    }
}

/// A handshake over the connection to the first hop: a proxy's, or the
/// origin's TLS.
#[derive(Debug)]
pub(crate) enum Handshake {
    Socks(socks::Socks),
    /// A SOCKS handshake about to start, the destination's name to come.
    SocksTarget(crate::conn::socks::Version),
    /// An HTTP proxy's tunnel, with `CONNECT`.
    Connect(tunnel::Tunnel),
    /// An HTTPS proxy's tunnel, with `CONNECT` as a stream of an HTTP/2
    /// session with it, which becomes the tunnel's layer.
    H2Connect(Box<crate::conn::h2proxy::H2Proxy>),
    /// An HTTP/3 proxy's tunnel, with `CONNECT` as a stream of the QUIC
    /// connection the race made to it, which becomes the tunnel's layer.
    /// The origin's QUIC connection through a CONNECT-UDP tunnel, over
    /// the capsule layer, which becomes the connection's HTTP/3 session.
    Quic(Box<crate::conn::quic::Quic>),
    /// The PROXY protocol's line, once the connection is up.
    Haproxy(haproxy::Preface),
    /// The origin's or an HTTPS proxy's TLS, whose state is the layer on
    /// the connection's stream.
    Tls(TlsSide),
}

impl Handshake {
    /// The filter C's chain holds for it.
    pub(super) fn filter(&self) -> Component {
        match self {
            Handshake::Socks(_) | Handshake::SocksTarget(_) => Component::Socks,
            Handshake::Connect(_) => Component::HttpProxy,
            Handshake::H2Connect(_) => Component::H2Proxy,
            Handshake::Quic(_) => Component::Http3,
            Handshake::Haproxy(_) => Component::Haproxy,
            Handshake::Tls(side) => side.filter(),
        }
    }

    /// What it waits for on the connection's socket, which `lease`
    /// holds: TLS's, what its layer says; the others', what they want as
    /// the layers below adjust it, an HTTPS proxy's TLS under a tunnel or
    /// the PROXY line.
    pub(super) fn interest(&self, setup: &ConnectMachine) -> Events {
        match self {
            Handshake::Socks(s) => setup.handshake_pollset(s.interest()),
            Handshake::SocksTarget(_) => setup.handshake_pollset(Events::NONE),
            Handshake::Connect(t) => setup.handshake_pollset(t.interest()),
            Handshake::H2Connect(p) => setup.handshake_pollset(p.connect_interest()),
            Handshake::Quic(q) => setup.handshake_pollset(q.wants()),
            Handshake::Haproxy(p) => setup.handshake_pollset(p.interest()),
            Handshake::Tls(_) => setup.handshake_pollset(Events::NONE),
        }
    }
}

/// How far a request got.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Reached {
    /// It was not made: DID's times are not taken.
    Unmade,
    /// It was being made, past DO (DOING or DOING_MORE): DID's times are
    /// not taken, but a connection it ends early on is in no known state
    /// (`mstate > MSTATE_DO`).
    Making,
    /// It was made; any exchange after did not run to its end.
    Made,
    /// Its exchange ran to its end (C's `req.done`): the last progress
    /// pass shows the meter however soon it comes.
    Exchanged,
}

impl Connecting {
    /// What the socket of the leading setup traces as: a race's second's
    /// is TCP's where the first dials QUIC. With the leading second gone,
    /// the first's, which runs on.
    pub(super) fn socket_component(&self) -> Component {
        self.lead()
            .or(self.lease.setup())
            .map_or(Component::Tcp, |m| m.dialing().socket_component())
    }

    /// Whether a race's second leads.
    fn second_leads(&self) -> bool {
        self.leader() == Attempt::Second
    }

    /// The attempt that leads: the first, unless a race's second does.
    pub(super) fn leader(&self) -> Attempt {
        self.race.as_ref().map_or(Attempt::First, |r| r.lead)
    }

    /// The attempt beside the lead, in a race.
    pub(super) fn beside(&self) -> Option<Attempt> {
        self.race.as_ref().map(|r| r.lead.other())
    }

    /// Attempt `a`'s machine, while it runs: the lease's first, or a
    /// race's second.
    pub(super) fn attempt(&self, a: Attempt) -> Option<&ConnectMachine> {
        match a {
            Attempt::First => self.lease.setup(),
            Attempt::Second => self.race.as_ref()?.second.running(),
        }
    }

    /// Attempt `a`'s machine, which runs.
    fn attempt_mut(&mut self, a: Attempt) -> &mut ConnectMachine {
        match a {
            Attempt::First => self.lease.setting_up(),
            Attempt::Second => self
                .race
                .as_mut()
                .and_then(|r| r.second.running_mut())
                .expect("the second runs"),
        }
    }

    /// The handshake under way over attempt `a`, if one is.
    pub(super) fn handshake(&self, a: Attempt) -> Option<&Handshake> {
        self.attempt(a)?.handshake.as_deref()
    }

    /// The leading setup's machine, while it runs: the lease's, or a
    /// race's second's once it leads.
    pub(super) fn lead(&self) -> Option<&ConnectMachine> {
        self.attempt(self.leader())
    }

    /// The leading setup, as it is about to start.
    pub(super) fn lead_mut(&mut self) -> &mut ConnectMachine {
        self.attempt_mut(self.leader())
    }

    /// The leading setup's handshake under way, if one is.
    pub(super) fn lead_handshake(&self) -> Option<&Handshake> {
        self.handshake(self.leader())
    }

    /// The leading setup failed, which a race of two outlives.
    fn lead_failed(&self) -> bool {
        match self.leader() {
            Attempt::Second => self.attempt(Attempt::Second).is_none(),
            Attempt::First => self.lease.setup_failed(),
        }
    }

    /// The setup beside the lead, while the race runs it: the second
    /// beside a leading first, or the first beside a leading second.
    pub(super) fn other(&self) -> Option<&ConnectMachine> {
        self.attempt(self.beside()?)
    }

    /// What the connection's layers answer `q`: the leading setup's, while
    /// it is set up.
    pub(super) fn query(&self, q: LayerQuery) -> Option<LayerAnswer> {
        if self.second_leads() {
            return self.lead()?.query(q);
        }
        self.lease.query(q)
    }

    /// Attempt `a` failed or was given up: its machine, to be discarded
    /// or closed, if it ran.
    fn fail_attempt(&mut self, a: Attempt) -> Option<ConnectMachine> {
        match a {
            Attempt::Second => self.race.as_mut()?.second.take_running(),
            Attempt::First => self.lease.fail_setup(),
        }
    }

    /// The attempt that lost to the one that made the connection: the
    /// lease's first, given back as the other's connection took its place
    /// (`displaced`), else the race's second.
    fn loser(&mut self, displaced: Option<ConnectMachine>) -> Option<ConnectMachine> {
        displaced.or_else(|| self.race.as_mut()?.second.take_running())
    }

    /// Move attempt `a`'s setup on by one event: the lease's, or a race's
    /// second's, whose connection, made, the lease takes, giving back the
    /// first's machine in `displaced`.
    fn connect_attempt(
        &mut self,
        a: Attempt,
        cx: &mut dyn crate::conn::ConnCx,
        options: DriveOptions,
        displaced: &mut Option<ConnectMachine>,
        step: impl FnOnce(
            ConnectMachine,
            &mut dyn crate::conn::ConnCx,
            DriveOptions,
        ) -> Result<Drove, ConnectError>,
    ) -> Result<Connected, ConnectError> {
        let Some(race) = self.race.as_deref_mut().filter(|_| a == Attempt::Second) else {
            return self.lease.connect(cx, options, step);
        };
        let machine = race.second.take_running().expect("the second runs");
        match step(machine, cx, options)? {
            Drove::Connecting(m, progress) => {
                race.second = RaceSecond::Running(m);
                Ok(Connected::Connecting(progress))
            }
            Drove::Established(conn) => {
                let (up, lost) = self.lease.adopt(conn);
                *displaced = lost;
                Ok(up)
            }
        }
    }

    /// Attempt `a`'s handshakes are made: the connection is up, in the
    /// lease, the first's machine given back in `displaced` if a race's
    /// second made it.
    fn handshaken(&mut self, a: Attempt, displaced: &mut Option<ConnectMachine>) -> Connected {
        let Some(race) = self.race.as_deref_mut().filter(|_| a == Attempt::Second) else {
            return self.lease.handshaken();
        };
        let conn = race
            .second
            .take_running()
            .expect("the second runs")
            .handshaken();
        let (up, lost) = self.lease.adopt(conn);
        *displaced = lost;
        up
    }

    /// The connection is up: on to the protocol's connect.
    pub(super) fn attached(self) -> TransferState {
        let Connecting {
            lease,
            proto,
            route,
            https: _,
            record: _,
            record_lookup: _,
            race,
            negotiate,
        } = self;
        assert!(race.is_none(), "the race is over once its winner is up");
        assert!(
            negotiate.is_none(),
            "a tunnel's Negotiate is the connection's once it is up"
        );
        TransferState::ProtoConnect(Attached {
            lease,
            proto,
            origin: Some(route.origin),
        })
    }
}

/// A step of the connection's setup (`multistate_connecting`): not while
/// receiving is paused, and not past the connect deadline
/// (`multi_handle_timeout`).
pub(super) fn connecting<H: Host>(
    run: &mut Run,
    c: Connecting,
    cx: &mut StepCx<'_, H>,
) -> (TransferState, Wake) {
    let (state, wake) = connecting_step(run, c, cx);
    // A resolver library's resolve held beside the setup times out only if
    // run again (`Curl_async_pollset`'s `EXPIRE_ASYNC_NAME`).
    if let TransferState::Connecting(c) = &state {
        let now = cx.rest.clock.now();
        let record = match &c.record_lookup {
            Some(RecordLookup::Library(r)) => Some(now.after(r.due(Duration::from_secs(1)))),
            _ => None,
        };
        let held = c.lead().and_then(|setup| setup.resolve_due(now));
        if let Some(at) = [record, held].into_iter().flatten().min() {
            arm(&mut run.deadlines, cx, TimerKind::AsyncName, at.since(now));
        }
    }
    (state, wake)
}

fn connecting_step<H: Host>(
    run: &mut Run,
    mut c: Connecting,
    cx: &mut StepCx<'_, H>,
) -> (TransferState, Wake) {
    let now = cx.rest.now;
    if let TimeLeft::Expired(_) = run.deadlines.time_left(starts(cx), now, Phase::Connecting) {
        let ms = cx.easy().report().timings().since_single_ms(now);
        let kind = ErrorKind::OperationTimedout;
        // C reads SOCKS5's GSS-API messages blocking, until its own check
        // of the time left fails the read.
        let lead = c.leader();
        let gss_read = match c.lead_handshake() {
            Some(Handshake::Socks(_)) => socks::timed_out(&mut c.shaking(lead).0, cx),
            _ => None,
        };
        let kind = match c.lead_handshake() {
            _ if let Some(failed) = gss_read => failed,
            Some(Handshake::Connect(_) | Handshake::H2Connect(_)) => trace::fail(
                cx,
                kind,
                format_args!("Proxy CONNECT aborted due to timeout"),
            ),
            Some(
                Handshake::Socks(_)
                | Handshake::SocksTarget(_)
                | Handshake::Haproxy(_)
                | Handshake::Tls(_)
                | Handshake::Quic(_),
            )
            | None => {
                // Named for the name, while it is not resolved yet.
                let what = match c.lead().map(ConnectMachine::resolving) {
                    Some(true) => "Resolving",
                    _ => "Connection",
                };
                trace::fail(
                    cx,
                    kind,
                    format_args!("{what} timed out after {ms} milliseconds"),
                )
            }
        };
        // What is known of a partly made connection is kept: TCP up, the
        // TLS handshake still under way.
        report_failed(cx, c.lead().and_then(ConnectMachine::partly_made));
        return (TransferState::Connecting(c).fail(kind), Wake::Again);
    }
    if StepCx::pause(cx).recv != RecvPause::Running {
        return (TransferState::Connecting(c), Wake::Idle);
    }
    // One call of C's `Curl_conn_connect`: on until the setup waits, is
    // up or fails.
    if let Err(kind) = https::connect_call(&mut c, cx) {
        return (TransferState::Connecting(c).fail(kind), Wake::Again);
    }
    // The chain's first connect reaches the name's DNS filter, which
    // starts (`cf_dns_start`).
    if c.lead().is_some_and(ConnectMachine::unasked) {
        names::started(cx, &c.route);
    }
    // The name's filter, below the record's, heads SETUP and the HTTPS
    // connect filter: what more came of the resolve the race goes on
    // beside is taken next. The first attempt holds it, whichever leads.
    if c.attempt(Attempt::First)
        .is_some_and(ConnectMachine::resolving)
    {
        let first = c.attempt_mut(Attempt::First);
        let polled = first.poll_late(&mut DriveCx::new(cx, None));
        match polled {
            Ok(Some(found)) => resolved(&c, run, cx, Attempt::First, found),
            Ok(None) => {}
            Err(OutOfMemory) => {
                return (
                    TransferState::Connecting(c).fail(ErrorKind::OutOfMemory),
                    Wake::Again,
                );
            }
        }
    }
    // Then the HTTPS connect filter's own connect.
    https::second_chosen(&mut c, cx);
    let mut c = c;
    if https::other_leads(&c) {
        c = match drive_other(run, c, cx) {
            Other::Racing(c) => c,
            Other::Up(state, wake) => return (state, wake),
        };
    }
    let mut entered = false;
    loop {
        // The attempt the lease held failed, and the race went on: the
        // second starts, the other attempt is waited for, or every one
        // failed.
        if c.lead_failed() {
            if https::second_due(&mut c, &mut run.deadlines, cx) && second_starts(&mut c) {
                continue;
            }
            if !https::other_leads(&c) {
                c = match drive_other(run, c, cx) {
                    Other::Racing(c) => c,
                    Other::Up(state, wake) => return (state, wake),
                };
            }
            let https = c.https;
            if let Some(kind) = https::all_failed(&c) {
                https::call_ended(https, cx, Err(kind));
                chain_connect_ended(cx, Err(kind));
                // Its attempts held apart, the chain ends with the HTTPS
                // connect filter; the first of them that connected at the
                // network level says when (`cf_hc_cntrl`).
                let chain = Chain::of(
                    crate::conn::Dialing {
                        route: &c.route,
                        dial: crate::conn::Dial::Stream,
                    },
                    head_of(&c),
                    SetupPoint::Resolving,
                    None,
                    true,
                );
                mstate::trace(cx, format_args!("failed to connect {}", chain.failed()));
                let partly = c.race.as_ref().and_then(|r| {
                    r.failed
                        .iter()
                        .chain(r.second.kept())
                        .find_map(ConnectMachine::partly_made)
                });
                report_failed(cx, partly);
                mstate::trace(
                    cx,
                    format_args!("connect failed -> {}", trace::Code(Err(kind))),
                );
                return (TransferState::Connecting(c).fail(kind), Wake::Again);
            }
            https::call_ended(https, cx, Ok(false));
            chain_connect_ended(cx, Ok(false));
            return (TransferState::Connecting(c), Wake::Idle);
        }
        if let Some(SetupPoint::Racing { started: false }) = c.lead().map(ConnectMachine::reached) {
            if https::awaiting(&c, cx) {
                https::call_ended(c.https, cx, Ok(false));
                chain_connect_ended(cx, Ok(false));
                return (TransferState::Connecting(c), Wake::Idle);
            }
            https::start(&mut c, &mut run.deadlines, cx);
            if race_starts(&mut c, cx).is_err() {
                return (
                    TransferState::Connecting(c).fail(ErrorKind::OutOfMemory),
                    Wake::Again,
                );
            }
        }
        let lead = c.leader();
        let chain = enter_setup(&c, cx, &mut entered, lead);
        let partly = c.lead().and_then(ConnectMachine::partly_made);
        let https = c.https;
        let (next, wake) = connect_once(run, c, cx, lead);
        match next {
            TransferState::Connecting(next) if wake == Wake::Again => c = next,
            TransferState::Done(ref d) => {
                let kind = d.result.expect_err("a setup is done with only as it fails");
                https::call_ended(https, cx, Err(kind));
                chain_connect_ended(cx, Err(kind));
                if let Some(chain) = chain {
                    // The HTTPS connect filter holds its attempt's
                    // filters apart from the chain once its call is over.
                    let chain = chain.failed();
                    mstate::trace(cx, format_args!("failed to connect {chain}"));
                }
                // What connected says when, after the chain
                // (`Curl_conn_report_failed`).
                report_failed(cx, partly);
                mstate::trace(
                    cx,
                    format_args!("connect failed -> {}", trace::Code(Err(kind))),
                );
                return (next, wake);
            }
            TransferState::Connecting(mut next) => {
                // The lease's attempt waits: the second may be due, and
                // is driven after it if it is out of the lease.
                if https::second_due(&mut next, &mut run.deadlines, cx) && second_starts(&mut next)
                {
                    c = next;
                    continue;
                }
                if !https::other_leads(&next) {
                    next = match drive_other(run, next, cx) {
                        Other::Racing(next) => next,
                        Other::Up(state, wake) => return (state, wake),
                    };
                }
                https::call_ended(https, cx, Ok(false));
                chain_connect_ended(cx, Ok(false));
                return (TransferState::Connecting(next), wake);
            }
            next => return (next, wake),
        }
    }
}

/// A call of the chain's connect ends, up, under way or failed, as the
/// filter at its top, the name's DNS one, traces it (`Curl_conn_connect`).
fn chain_connect_ended<H: Host>(cx: &mut StepCx<'_, H>, ended: Result<bool, ErrorKind>) {
    connect_ended_at(cx, Component::DnsFilter, ended);
}

/// The same, `top` the filter at the chain's top.
pub(super) fn connect_ended_at<H: Host>(
    cx: &mut StepCx<'_, H>,
    top: Component,
    ended: Result<bool, ErrorKind>,
) {
    let (code, done) = match ended {
        Ok(done) => (trace::Code(Ok(())), u8::from(done)),
        Err(kind) => (trace::Code(Err(kind)), 0),
    };
    trace::of(
        cx,
        top,
        format_args!("Curl_conn_connect(block=0) -> {code}, done={done}"),
    );
    if ended.is_err() {
        trace::of(
            cx,
            top,
            format_args!("Curl_conn_connect(), filter returned {code}"),
        );
    }
}

/// What heads the setup's chain above its setup filter.
fn head_of(c: &Connecting) -> Head {
    Head {
        https: c.https.is_some(),
        record: c.https.is_some_and(|h| h.asks()),
        h2: false,
    }
}

/// Attempt `a`'s name resolved, found as `found` says: said, and timed.
fn resolved<H: Host>(
    c: &Connecting,
    run: &mut Run,
    cx: &mut StepCx<'_, H>,
    a: Attempt,
    found: Found,
) {
    run.deadlines.clear(TimerKind::AsyncName);
    // A Unix socket's address is made, not looked up (`resolv_unix`).
    if !c.route.destination().is_unix() {
        trace_lookup(cx, &c.route, Some(found));
        if let Found::Stale(asked) | Found::Resolved(asked) = found {
            let answer = c.attempt(a).and_then(|m| m.answer().cloned());
            trace_resolved(cx, &c.route, Some(asked), answer.as_deref());
        }
    }
    cx.mark(Timer::NameLookup);
    report_answer(cx, c);
}

/// SETUP's connect is entered (`cf_setup_connect`), and traces the chain
/// C would have: once the name is resolved, at the first connect of a
/// call, again as it adds a filter, and as it starts over. Returns the
/// chain as the connect goes on to, for its failure to name.
fn enter_setup<H: Host>(
    c: &Connecting,
    cx: &mut StepCx<'_, H>,
    entered: &mut bool,
    a: Attempt,
) -> Option<Chain> {
    let setup = c.attempt(a)?;
    let under_way = c.handshake(a).map(Handshake::filter);
    Some(enter_chain(
        setup,
        &c.route,
        head_of(c),
        under_way,
        cx,
        entered,
    ))
}

/// SETUP's connect entered over `chain`: its line, then, while the
/// tunnel through a proxy is to be made, the HTTP-PROXY filter's under it
/// (`cf_setup_connect`, `http_proxy_cf_connect`'s `CONNECT`, `CONNECT-UDP`
/// for a tunnel of datagrams).
fn setup_entered<H: Host>(cx: &mut StepCx<'_, H>, chain: Chain, udp: bool) {
    mstate::trace(cx, format_args!("cf_setup_connect {chain}"));
    if chain.connects(Component::HttpProxy) {
        let what = if udp { "CONNECT-UDP" } else { "CONNECT" };
        trace::of(cx, Component::HttpProxy, format_args!("{what}"));
    }
}

/// `enter_setup` of the chain `setup` makes over `plan`, under `head`,
/// with the handshake `under_way` started.
pub(super) fn enter_chain<H: Host>(
    setup: &ConnectMachine,
    plan: &NetRoute,
    head: Head,
    under_way: Option<Component>,
    cx: &mut StepCx<'_, H>,
    entered: &mut bool,
) -> Chain {
    let reached = setup.reached();
    let rank = cx.rank();
    // The route as the attempt dials it, which a race's second dials
    // otherwise than the first.
    let route = setup.dialing();
    let chain = |reached, under_way, installed| {
        Chain::of(route, head, reached, under_way, installed).on(rank)
    };
    let udp = route.asks_udp();
    let entry = |cx: &mut StepCx<'_, H>, chain: Chain| setup_entered(cx, chain, udp);
    match reached {
        SetupPoint::Resolving => return chain(reached, None, true),
        SetupPoint::Racing { started: false } => {
            // The happy eyeballs filter is added (`cf_setup_add_ip_happy`).
            entry(cx, chain(reached, None, true));
            let peer = plan.destination();
            let to = if plan.proxy_over_quic() {
                "HTTP/3 proxy"
            } else if plan.proxy.as_ref().is_some_and(|p| p.tunnels()) {
                "proxy"
            } else {
                "origin"
            };
            let at = port_text(peer.port());
            trace::of_with(
                cx,
                Component::Setup,
                &[
                    b"happy eyeballing to ",
                    to.as_bytes(),
                    b" ",
                    peer.name(),
                    at.bytes(),
                ],
            );
            let racing = chain(SetupPoint::Racing { started: true }, None, true);
            entry(cx, racing);
            *entered = true;
            return racing;
        }
        SetupPoint::Racing { started: true } | SetupPoint::Dialed(_) => {}
    }
    if !*entered {
        entry(cx, chain(reached, under_way, true));
        *entered = true;
    }
    let (SetupPoint::Dialed(made), None) = (reached, under_way) else {
        return chain(reached, under_way, true);
    };
    let Some(due) = handshake_due(plan, setup, made) else {
        return chain(reached, None, true);
    };
    // The tunnel's filter was added with the HTTPS proxy's TLS below it,
    // and goes on connecting in the same call.
    if let Due::Tunnel = due
        && made.proxy_tls
    {
        return chain(reached, Some(Component::HttpProxy), false);
    }
    let filter = match due {
        Due::Socks(_) => {
            let leg = plan.socks().expect("through a SOCKS proxy");
            if leg.version.resolves_locally() && !made.target_filter {
                names::target_created(cx, leg.to, leg.version.ip(plan.ip));
            }
            let at = port_text(leg.to.port());
            trace::of_with(
                cx,
                Component::Setup,
                &[b"added SOCKS filter to ", leg.to.name(), at.bytes()],
            );
            Component::Socks
        }
        Due::Tunnel => {
            trace::of(
                cx,
                Component::Setup,
                format_args!("added HTTP proxy tunnel filter"),
            );
            Component::HttpProxy
        }
        Due::Preface => {
            trace::of(cx, Component::Setup, format_args!("added HAPROXY filter"));
            Component::Haproxy
        }
        // An HTTPS proxy's TLS below its tunnel is added with it
        // (`cf_setup_add_http_proxy`); one requests go whole to is the
        // origin's filter (`cf_setup_add_origin_filters`), whose line says
        // so though the TLS is the proxy's.
        Due::Tls(TlsSide::Proxy) if plan.proxy.as_ref().is_some_and(|p| p.tunnels()) => {
            trace::of(
                cx,
                Component::Setup,
                format_args!("added SSL filter for HTTP proxy"),
            );
            trace::of(
                cx,
                Component::Setup,
                format_args!("added HTTP proxy tunnel filter"),
            );
            Component::SslProxy
        }
        Due::Tls(side) => {
            trace::of(
                cx,
                Component::Setup,
                format_args!("added SSL filter for origin"),
            );
            side.filter()
        }
        // The capsule filter goes in with it, below.
        Due::Quic => {
            trace::of(
                cx,
                Component::Setup,
                format_args!("added QUIC filter for origin"),
            );
            Component::Http3
        }
    };
    // The tunnel's filter installs its HTTP/1.1 one as it first connects.
    entry(cx, chain(reached, Some(filter), false));
    chain(reached, Some(filter), true)
}

/// One step of attempt `a`'s setup within a call: a handshake's, the
/// next handshake started, or a drive of the connect machine. Only the
/// lead's clears the race's timer as it connects.
fn connect_once<H: Host>(
    run: &mut Run,
    mut c: Connecting,
    cx: &mut StepCx<'_, H>,
    a: Attempt,
) -> (TransferState, Wake) {
    share_addresses(&mut c);
    if c.handshake(a).is_some() {
        let shook = {
            let (mut s, mut t) = c.shaking(a);
            step_handshake(&mut s, &mut t, cx)
        };
        return c.shook(a, shook, cx);
    }
    if let Some(SetupPoint::Dialed(_)) = c.attempt(a).map(ConnectMachine::reached) {
        return handshake_next(c, cx, a);
    }
    let setup = drive_options(cx);
    let mut displaced = None;
    // An HTTP/3 proxy's tunnels are the race's attempts, checked first.
    let mut connected = match tunnels_drive(&mut c, cx, a) {
        Ok(Tunnels::Idle) => c.connect_attempt(
            a,
            &mut DriveCx::new(cx, Some(&mut run.deadlines)),
            setup,
            &mut displaced,
            ConnectMachine::drive,
        ),
        decided => tunnel_decided(&mut c, a, run, cx, &mut displaced, decided),
    };
    // A QUIC connection to the proxy made, its tunnel's `CONNECT` goes
    // in the same check (`cf_h3_proxy_connect`).
    if let Ok(Connected::Connecting(Progress::Tunnel { until })) = connected {
        connected = match tunnels_drive(&mut c, cx, a) {
            Ok(Tunnels::Idle) => {
                // The attempt runs on, its tunnel asked for: the race says
                // what it checked, as C's does once the baller's connect
                // returns.
                if let Some(m) = c.attempt(a) {
                    m.checked(cx);
                }
                Ok(Connected::Connecting(Progress::Waiting { until }))
            }
            decided => tunnel_decided(&mut c, a, run, cx, &mut displaced, decided),
        };
    }
    // The race is over once an attempt connects, a proxy's or not
    // (`cf_ip_happy_connect`).
    if a == c.leader()
        && !matches!(
            connected,
            Ok(Connected::Connecting(
                Progress::Resolved(_)
                    | Progress::Trying { .. }
                    | Progress::Failed
                    | Progress::Waiting { .. }
                    | Progress::Tunnel { .. }
                    | Progress::Resolving { .. }
            ))
        )
    {
        run.deadlines.clear(TimerKind::Eyeballs);
    }
    match connected {
        Ok(Connected::Connecting(Progress::Resolved(found))) => {
            resolved(&c, run, cx, a, found);
            (TransferState::Connecting(c), Wake::Again)
        }
        // The drive traced the failure.
        Ok(Connected::Connecting(Progress::Failed)) => (TransferState::Connecting(c), Wake::Again),
        Ok(Connected::Connecting(Progress::Trying { at_once, until, .. })) => {
            if at_once {
                return (TransferState::Connecting(c), Wake::Again);
            }
            // A connect under way is polled at the next call.
            waiting(run, cx, until);
            (TransferState::Connecting(c), Wake::Idle)
        }
        Ok(Connected::Connecting(Progress::Dialed)) => {
            let (remote, _) = c.attempt_mut(a).dialed().ends();
            eyeballs_won(cx, &c.route, &remote);
            (TransferState::Connecting(c), Wake::Again)
        }
        Ok(Connected::Connecting(Progress::Waiting { until } | Progress::Tunnel { until })) => {
            waiting(run, cx, until);
            (TransferState::Connecting(c), Wake::Idle)
        }
        // The resolver's answer wakes the multi; a thread it could not
        // start is tried for again at `retry`, or the connect limit's
        // own timer ends the wait (`Curl_async_pollset`).
        Ok(Connected::Connecting(Progress::Resolving { retry, aaaa })) => {
            match retry {
                Some(at) => name_retry(run, cx, at),
                None => run.deadlines.clear(TimerKind::AsyncName),
            }
            if let Some(at) = aaaa {
                let wait = wait_ms(cx.now(), at);
                arm(&mut run.deadlines, cx, TimerKind::Eyeballs, wait);
            }
            (TransferState::Connecting(c), Wake::Idle)
        }
        Ok(Connected::Established { remote, local, at }) => {
            eyeballs_won(cx, &c.route, &remote);
            let lost = c.loser(displaced);
            up(c, cx, remote, local, at, false, lost)
        }
        // A reused connection is up: nothing to trace or time
        // (`Curl_conn_connect` returns before `conn_connect_trace`).
        Ok(Connected::AlreadyUp { remote, local }) => {
            if let Some(remote) = remote {
                cx.report_mut().set_primary(Ends { remote, local });
            }
            (c.attached(), Wake::Again)
        }
        Err(e) => {
            let kind = connect_failed(cx, &c.route, e);
            if a != c.leader() {
                // The drive let the attempt go.
                https::other_failed(&mut c, kind);
                return (TransferState::Connecting(c), Wake::Idle);
            }
            attempt_failed(c, cx, a, kind)
        }
    }
}

/// Attempt `a`'s race's tunnels through an HTTP/3 proxy moved on, if
/// its setup races.
fn tunnels_drive<H: Host>(
    c: &mut Connecting,
    cx: &mut StepCx<'_, H>,
    a: Attempt,
) -> Result<Tunnels, OutOfMemory> {
    let racing = c
        .attempt(a)
        .is_some_and(|m| matches!(m.reached(), SetupPoint::Racing { .. }));
    if !racing {
        return Ok(Tunnels::Idle);
    }
    let (s, mut lent) = c.shaking(a);
    h3tunnel::drive(s.machine, &mut lent, cx)
}

/// A tunnel through an HTTP/3 proxy decided, or a drive of them out of
/// memory: the setup moves on with it.
fn tunnel_decided<H: Host>(
    c: &mut Connecting,
    a: Attempt,
    run: &mut Run,
    cx: &mut StepCx<'_, H>,
    displaced: &mut Option<ConnectMachine>,
    decided: Result<Tunnels, OutOfMemory>,
) -> Result<Connected, ConnectError> {
    let setup = drive_options(cx);
    let mut dcx = DriveCx::new(cx, Some(&mut run.deadlines));
    match decided {
        Ok(Tunnels::Idle) => unreachable!("an undecided drive moves the setup on"),
        Ok(Tunnels::Through(i)) => c.connect_attempt(a, &mut dcx, setup, displaced, |m, cx, o| {
            m.tunneled(cx, o, i)
        }),
        Ok(Tunnels::Failed(i, kind)) => {
            c.connect_attempt(a, &mut dcx, setup, displaced, |m, cx, _| {
                m.tunnel_failed(cx, i, kind)
            })
        }
        Err(OutOfMemory) => Err(ConnectError::OutOfMemory),
    }
}

/// What a drive of a setup is told of the transfer's options.
pub(crate) fn drive_options<H: Host>(cx: &mut StepCx<'_, H>) -> DriveOptions {
    let options = cx.easy().options();
    DriveOptions {
        wildcard: cx.easy().wildcard_resolve,
        max_age: options.limits.reuse.dns_max_age,
        delay: options.limits.eyeballs.0,
        scope: options.address_scope,
        socket: crate::conn::SocketSetup::of(&options.sockets),
        haproxy: options.proxy.haproxy,
        #[cfg(test)]
        layer: options.layer,
        #[cfg(any(test, feature = "test-util"))]
        linger: cx.rest.linger,
    }
}

/// Attempt `a` failed with `kind`, traced: the transfer fails, unless it
/// races another attempt, which goes on (`cf_hc_connect`). The lead's
/// failure is weighed for the race; the other's is let go.
pub(super) fn attempt_failed<H: Host>(
    mut c: Connecting,
    cx: &mut StepCx<'_, H>,
    a: Attempt,
    kind: ErrorKind,
) -> (TransferState, Wake) {
    let lead = a == c.leader();
    if lead && (c.race.is_none() || !https::attempt_failed(&mut c, kind)) {
        return (TransferState::Connecting(c).fail(kind), Wake::Again);
    }
    // A handshake's failure leaves its setup running: its connection is
    // kept until the race ends.
    if let Some(mut lost) = c.fail_attempt(a) {
        match (&mut c.race, lost.reached()) {
            (Some(race), SetupPoint::Dialed(_)) => {
                // No one drives it again: what its handshake held goes now.
                lost.handshake = None;
                match a {
                    Attempt::First => {
                        assert!(race.failed.is_none(), "an attempt fails once");
                        race.failed = Some(lost);
                    }
                    Attempt::Second => race.second = RaceSecond::Kept(lost),
                }
            }
            _ => lost.discard(&mut DriveCx::new(cx, None)),
        }
    }
    if lead {
        (TransferState::Connecting(c), Wake::Again)
    } else {
        https::other_failed(&mut c, kind);
        (TransferState::Connecting(c), Wake::Idle)
    }
}

/// The race starts with its first attempt, in the lease, where a second
/// may follow: what the second is made from is kept.
fn race_starts<H: Host>(c: &mut Connecting, cx: &StepCx<'_, H>) -> Result<(), OutOfMemory> {
    if c.race.is_some() || !https::may_race(c, cx) {
        return Ok(());
    }
    let at = cx.now();
    let (Some(answer), Some(makings)) = (
        c.lead().and_then(|m| m.addresses().cloned()),
        c.lead().map(ConnectMachine::makings),
    ) else {
        unreachable!("an attempt starts once what it connects to is known");
    };
    c.race = Some(curl_alloc::try_box(Race {
        answer,
        makings,
        second: RaceSecond::Unstarted,
        lead: Attempt::First,
        at,
        first_failed: None,
        failed: None,
        replied: false,
    })?);
    Ok(())
}

/// The second attempt starts beside the first, racing the addresses the
/// first resolved (`cf_hc_baller_init`): one over TCP leads from now on,
/// one over QUIC runs beside the first over TCP. Whether it leads, to be
/// driven as the lead.
fn second_starts(c: &mut Connecting) -> bool {
    let alpn = https::second_started(c);
    let race = c.race.as_mut().expect("a race of two");
    let route = c.route.clone();
    let dial = match alpn {
        https::Alpn::H3 => Dial::Quic,
        https::Alpn::H2 | https::Alpn::H1 => Dial::Stream,
    };
    let (closer, settings, created) = race.makings.clone();
    let number = c.lease.number();
    let second = ConnectMachine::racing(
        number,
        route,
        dial,
        created,
        closer,
        settings,
        race.answer.clone(),
    );
    assert!(
        matches!(race.second, RaceSecond::Unstarted),
        "one second attempt"
    );
    race.second = RaceSecond::Running(second);
    if alpn == https::Alpn::H3 {
        return false;
    }
    race.lead = Attempt::Second;
    true
}

/// What a drive of the setup beside the lead came to.
enum Other {
    /// The setup goes on.
    Racing(Connecting),
    /// It made the connection, which is up.
    Up(TransferState, Wake),
}

/// The race's attempt beside the lead is driven in its turn as C's
/// filter drives its ballers (`cf_hc_connect`): before the lead if it is
/// the first, after it if the second, as the lead is, on until it waits:
/// its connect, then its handshakes. Its failure is its own; the
/// transfer's step ends here if it made the connection.
/// The second attempt of a race is given what the first's resolve has found
/// by now, and told whether more may come.
fn share_addresses(c: &mut Connecting) {
    let first = c.attempt(Attempt::First);
    let resolving = first.is_some_and(ConnectMachine::resolving);
    let answer = first.and_then(|m| m.answer().cloned());
    let Some(race) = c.race.as_mut() else {
        return;
    };
    if let Some(answer) = answer {
        race.answer = Addresses::Resolved(answer);
    }
    if let (Addresses::Resolved(answer), Some(second)) = (&race.answer, race.second.running_mut()) {
        second.follow(answer.clone(), resolving);
    }
}

fn drive_other<H: Host>(run: &mut Run, mut c: Connecting, cx: &mut StepCx<'_, H>) -> Other {
    let Some(a) = c.beside() else {
        return Other::Racing(c);
    };
    loop {
        let Some(other) = c.attempt(a) else {
            return Other::Racing(c);
        };
        // Its chain is traced as SETUP's connect enters it: while it
        // races, its own; dialed, with the handshake it adds.
        let mut entered = false;
        if let SetupPoint::Dialed(_) = other.reached() {
            enter_setup(&c, cx, &mut entered, a);
        } else {
            let chain = Chain::of(other.dialing(), head_of(&c), other.reached(), None, true);
            setup_entered(cx, chain, other.dialing().asks_udp());
        }
        match connect_once(run, c, cx, a) {
            (TransferState::Connecting(next), Wake::Again) => c = next,
            (TransferState::Connecting(next), _) => return Other::Racing(next),
            (state, wake) => return Other::Up(state, wake),
        }
    }
}

/// Connected to the first hop, or a handshake over it made: the next
/// handshake starts, in cf-setup.c's order, which is decided here alone:
/// the SOCKS proxy's, (the HTTP proxy's TLS, with step 43), the HTTP
/// proxy's tunnel, the PROXY protocol's line, the origin's TLS. With
/// none left, the connection is open.
fn handshake_next<H: Host>(
    mut c: Connecting,
    cx: &mut StepCx<'_, H>,
    a: Attempt,
) -> (TransferState, Wake) {
    let made = c.attempt_mut(a).dialed().made();
    let setup = c.attempt(a).expect("a handshake is due over a setup");
    if let Some(due) = handshake_due(&c.route, setup, made) {
        let started = {
            let (mut s, mut t) = c.shaking(a);
            start_handshake(&mut s, &mut t, cx, due)
        };
        return c.shook(a, started, cx);
    }
    // The origin's QUIC connection made through the tunnel is the
    // connection's session.
    let h3 = match c.attempt_mut(a).dialed().take_quic() {
        Some(quic) => match curl_alloc::try_box(crate::proto::http3::H3Conn::new(quic)) {
            Ok(h3) => Some(h3),
            Err(OutOfMemory) => {
                return (
                    TransferState::Connecting(c).fail(ErrorKind::OutOfMemory),
                    Wake::Again,
                );
            }
        },
        None => None,
    };
    let preface = c.attempt(a).is_some_and(ConnectMachine::sends_preface);
    let mut displaced = None;
    let up_at = c.handshaken(a, &mut displaced);
    if let Some(h3) = h3 {
        c.lease.get().put_h3(h3);
    }
    let lost = c.loser(displaced);
    match up_at {
        Connected::Established {
            remote, local, at, ..
        } => up(c, cx, remote, local, at, preface, lost),
        _ => unreachable!("the handshakes make the connection"),
    }
}

/// A handshake still to make over a dialed connection.
#[derive(Clone, Copy)]
pub(super) enum Due {
    Socks(crate::conn::socks::Version),
    Tunnel,
    Preface,
    Tls(TlsSide),
    /// The origin's QUIC connection, through a CONNECT-UDP tunnel.
    Quic,
}

/// The handshake to make next over `setup`, over `route`, which made
/// `made`, in cf-setup.c's order; none once they are all made.
pub(super) fn handshake_due(route: &NetRoute, setup: &ConnectMachine, made: Made) -> Option<Due> {
    if let Some(version) = route.socks().map(|leg| leg.version)
        && !made.socks
    {
        return Some(Due::Socks(version));
    }
    let tunnels = route.proxy.as_ref().is_some_and(|p| p.tunnels());
    let proxy_tls = route.proxy_tls().is_some() && !made.proxy_tls;
    if proxy_tls && tunnels {
        return Some(Due::Tls(TlsSide::Proxy));
    }
    if tunnels && made.tunnel.is_none() {
        return Some(Due::Tunnel);
    }
    if setup.sends_preface() && !made.preface {
        return Some(Due::Preface);
    }
    // Requests go whole to the HTTPS proxy: its TLS is the origin's
    // filter, the last but for none.
    if proxy_tls {
        return Some(Due::Tls(TlsSide::Proxy));
    }
    // Through a CONNECT-UDP tunnel, the origin's TLS is its QUIC
    // connection's.
    if setup.dialing().tunnels_udp() {
        return (!made.quic).then_some(Due::Quic);
    }
    if route.tls.is_some() && !made.tls {
        return Some(Due::Tls(TlsSide::Origin));
    }
    None
}

/// The handshake `due` starts over a setup.
pub(super) fn start_handshake<H: Host>(
    s: &mut SetupMut<'_>,
    t: &mut Lent<'_>,
    cx: &mut StepCx<'_, H>,
    due: Due,
) -> Result<Wake, Failure> {
    match due {
        Due::Socks(version) => socks::dialed(s, t, cx, version),
        Due::Tunnel => tunnel::dialed(s, t, cx),
        Due::Preface => haproxy::start(s, t, cx),
        Due::Tls(side) => tls::start(s, t, cx, side),
        Due::Quic => quictunnel::start(s, t, cx),
    }
}

/// The handshake under way over a setup moves on, by its driver.
pub(super) fn step_handshake<H: Host>(
    s: &mut SetupMut<'_>,
    t: &mut Lent<'_>,
    cx: &mut StepCx<'_, H>,
) -> Result<Wake, Failure> {
    let under_way = match s.handshake.as_deref().expect("a handshake under way") {
        Handshake::Socks(_) => socks::step,
        Handshake::SocksTarget(_) => socks::awaited,
        Handshake::Connect(_) => tunnel::step,
        Handshake::H2Connect(_) => h2tunnel::step,
        Handshake::Quic(_) => quictunnel::step,
        Handshake::Haproxy(_) => haproxy::step,
        &Handshake::Tls(side) => return tls::step(s, t, cx, side),
    };
    under_way(s, t, cx)
}

/// The name `route` connects to first, missing from the cache, is not
/// resolved for IPv6 alone without IPv6 (`can_resolve_dns_queries`).
fn no_ipv6<H: Host>(cx: &mut StepCx<'_, H>, route: &NetRoute, proxy: bool) -> ErrorKind {
    trace_lookup(cx, route, Some(Found::Resolved(Asked::Resolver(None))));
    let peer = route.destination();
    let (host, at) = (peer.name(), port_text(peer.port()));
    let queries = queries(peer, route.ip, cx.rest.ipv6_works);
    let kind = if proxy {
        ErrorKind::CouldntResolveProxy
    } else {
        ErrorKind::CouldntResolveHost
    };
    let code = trace::Code(Err(kind));
    let dns = Component::Dns;
    trace::of(
        cx,
        dns,
        format_args!("[{queries}] hostip_resolv started -> {code}"),
    );
    let kind = trace::fail_with(cx, kind, &[b"Could not resolve: ", host, at.bytes()]);
    trace::fail_with(cx, kind, &[b"Could not resolve: ", host])
}

/// `:port`, as a line shows it after a name.
fn port_text(port: u16) -> Text<8> {
    Text::clipped(format_args!(":{port}")).0
}

/// The debug build failed the resolve of IPv6 addresses alone of the name
/// `route` connects to first, before the cache was looked in
/// (`hostip_resolv`, `CURL_DBG_RESOLV_FAIL_IPV6`).
fn debug_failed_ipv6<H: Host>(cx: &mut StepCx<'_, H>, route: &NetRoute, proxy: bool) -> ErrorKind {
    let peer = route.destination();
    let (host, at) = (peer.name(), port_text(peer.port()));
    // The C debug build's line, which the lookup said in a debug build;
    // said here in any other, as only a debug build fails the resolve.
    #[cfg(not(feature = "debug-hooks"))]
    {
        let queries = queries(peer, route.ip, cx.rest.ipv6_works).as_bytes();
        trace::of_with(
            cx,
            Component::Dns,
            &[b"[", queries, b"] hostip_resolv(", host, at.bytes(), b")"],
        );
    }
    trace::info(cx, format_args!("DEBUG fail ipv6 resolve"));
    let (what, kind): (&[u8], _) = if proxy {
        (b"proxy", ErrorKind::CouldntResolveProxy)
    } else {
        (b"host", ErrorKind::CouldntResolveHost)
    };
    let kind = trace::fail_with(cx, kind, &[b"Could not resolve ", what, b": ", host]);
    let kind = trace::fail_with(cx, kind, &[b"Could not resolve: ", host, at.bytes()]);
    trace::fail_with(cx, kind, &[b"Could not resolve: ", host])
}

/// The name `route` connects to first was looked up in the cache, whose
/// lines the lookup said as it looked (`hostip_resolv`,
/// `Curl_dnscache_get`): what is left is the queries of a resolve that
/// queued its own and said none as it went.
fn trace_lookup<H: Host>(cx: &mut StepCx<'_, H>, route: &NetRoute, found: Option<Found>) {
    if let Some(
        Found::Stale(Asked::Resolver(Some(q))) | Found::Resolved(Asked::Resolver(Some(q))),
    ) = found
    {
        let peer = route.destination();
        let (name, at) = (peer.name(), port_text(peer.port()));
        let xfer = cx.easy().report().transfer_number().map_or(0, |n| n.get());
        let dns = Component::Dns;
        crate::conn::say_queued(xfer, q, name, at.bytes(), &mut |parts| {
            trace::of_with(cx, dns, parts);
        });
    }
}

/// A second connection's `setup` moves on by one event, as the
/// transfer's own does: through the names the transfer keeps, its
/// share's if it shares them.
pub(crate) fn side_drive<H: Host>(
    cx: &mut StepCx<'_, H>,
    setup: ConnectMachine,
) -> Result<Drove, ConnectError> {
    let options = drive_options(cx);
    setup.drive(&mut DriveCx::new(cx, None), options)
}

/// What one of a second connection's waits asks of its timer.
#[derive(Clone, Copy, Debug, Default)]
pub(crate) enum SideTimer {
    /// Nothing: it stays as it is.
    #[default]
    Keep,
    /// To fire then.
    Arm(Instant),
    /// To fire no more.
    Clear,
}

/// What a second connection's setup, which holds no timers, asks of the
/// transfer's: its next attempt's and its resolver's next try, as the
/// transfer's own setup arms them.
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct SideDue {
    pub(super) eyeballs: SideTimer,
    pub(super) name: SideTimer,
}

/// A second connection's setup over `route` moved on as `progress` says:
/// what its waits ask of the transfer's timers noted for the step's end.
/// `dialed` names the peer it dialed, if it did.
pub(crate) fn side_progress<H: Host>(
    cx: &mut StepCx<'_, H>,
    route: &NetRoute,
    progress: &Progress,
    dialed: impl FnOnce() -> Remote,
) {
    let due = &mut cx.side_due;
    match *progress {
        Progress::Resolved(_) => due.name = SideTimer::Clear,
        Progress::Trying { until, .. }
        | Progress::Waiting { until }
        | Progress::Tunnel { until } => {
            if let Some(at) = until {
                due.eyeballs = SideTimer::Arm(at);
            }
        }
        Progress::Resolving { retry, aaaa } => {
            if let Some(at) = aaaa {
                due.eyeballs = SideTimer::Arm(at);
            }
            due.name = retry.map_or(SideTimer::Clear, SideTimer::Arm);
        }
        Progress::Dialed => side_won(cx, route, &dialed()),
        Progress::Failed => {}
    }
}

/// A second connection's attempt to `remote` connected: the race is over,
/// said as the transfer's is; the connection is counted once it is up.
pub(crate) fn side_won<H: Host>(cx: &mut StepCx<'_, H>, route: &NetRoute, remote: &Remote) {
    cx.side_due.eyeballs = SideTimer::Clear;
    said_won(cx, route, remote);
}

/// What the step's second connection asked of the timers, now that `run`
/// is at hand: armed as the transfer's own setup arms them.
pub(crate) fn side_timers<H: Host>(run: &mut Run, cx: &mut StepCx<'_, H>) {
    let SideDue { eyeballs, name } = std::mem::take(&mut cx.side_due);
    match eyeballs {
        SideTimer::Keep => {}
        SideTimer::Arm(at) => cx.as_second(|cx| eyeballs_due(run, cx, at)),
        SideTimer::Clear => run.deadlines.clear(TimerKind::Eyeballs),
    }
    match name {
        SideTimer::Keep => {}
        SideTimer::Arm(at) => cx.as_second(|cx| name_retry(run, cx, at)),
        SideTimer::Clear => run.deadlines.clear(TimerKind::AsyncName),
    }
}

/// The name a second connection's `setup` connects to first was found,
/// as `found` says: traced as the transfer's own connection traces it.
pub(crate) fn side_resolved<H: Host>(cx: &mut StepCx<'_, H>, setup: &ConnectMachine, found: Found) {
    let route = setup.route();
    if route.destination().is_unix() {
        return;
    }
    trace_lookup(cx, route, Some(found));
    if let Found::Stale(asked) | Found::Resolved(asked) = found {
        trace_resolved(cx, route, Some(asked), setup.answer().map(|a| &**a));
    }
}

/// The name `route` connects to first was resolved, `asked` what
/// answered, to `answer`, which was kept; or, with none, the resolver
/// failed. A shortcut answers at once; the resolver,
/// as the reference build's c-ares does, answers later (`CURLE_AGAIN`),
/// its polls not traced.
fn trace_resolved<H: Host>(
    cx: &mut StepCx<'_, H>,
    route: &NetRoute,
    asked: Option<Asked>,
    answer: Option<&crate::conn::Answer>,
) {
    let addrs = answer.map_or(&[][..], |a| a.addrs());
    let peer = route.destination();
    let (name, at, queries) = (
        peer.name(),
        port_text(peer.port()),
        queries(peer, route.ip, cx.rest.ipv6_works),
    );
    let at = at.bytes();
    let code = match asked {
        Some(Asked::Shortcut | Asked::InStart) => 0,
        Some(Asked::Resolver(_) | Asked::Doh) | None => crate::error::AGAIN_NUMBER,
    };
    let dns = Component::Dns;
    // Said with the start, for an answer taken in it or had at once.
    if !matches!(asked, Some(Asked::Doh | Asked::InStart | Asked::Shortcut)) {
        trace::of(
            cx,
            dns,
            format_args!("[{queries}] hostip_resolv started -> {code}"),
        );
    }
    if let Some(Asked::Resolver(Some(q))) = asked {
        crate::conn::say_answered(q, name, at, addrs, &mut |parts| {
            trace::of_with(cx, dns, parts);
        });
    }
    let Some(asked) = asked else {
        return;
    };
    if let Asked::Resolver(_) | Asked::Doh = asked {
        // Shuffled as the entry was made, before the take was done
        // (`dnsc_entry_assign_addr`).
        if answer.is_some_and(|a| a.shuffled()) {
            let n = addrs.len();
            trace::of(cx, dns, format_args!("Shuffling {n} addresses"));
        }
        trace::of_with(
            cx,
            dns,
            &[
                b"[",
                queries.as_bytes(),
                b"] resolve complete for ",
                name,
                at,
            ],
        );
    }
    // Said as it was kept, around the cache's lock.
    if asked == Asked::Shortcut {
        return;
    }
    trace::of_with(
        cx,
        dns,
        &[
            b"cached entry for ",
            name,
            at,
            b" queries=",
            queries.as_bytes(),
        ],
    );
}

/// An attempt waits for its sockets, and until `until` for its next
/// attempt to be due, if one is left: the race's timer is armed for it.
/// With none left the timer stays as it was, armed for an attempt that
/// went before, until it fires or the race is won: C's
/// `cf_ip_ballers_run` only ever arms it.
pub(super) fn waiting<H: Host>(run: &mut Run, cx: &mut StepCx<'_, H>, until: Option<Instant>) {
    if let Some(at) = until {
        eyeballs_due(run, cx, at);
    }
}

/// The resolver is tried again at `at`: its timer armed for then, or for
/// the end of the time left to connect if that comes first.
fn name_retry<H: Host>(run: &mut Run, cx: &mut StepCx<'_, H>, at: Instant) {
    let mut wait = wait_ms(cx.now(), at);
    let left = run
        .deadlines
        .time_left(starts(cx), cx.now(), Phase::Connecting);
    if let TimeLeft::Remaining(left) = left {
        wait = wait.min(left);
    }
    arm(&mut run.deadlines, cx, TimerKind::AsyncName, wait);
}

/// The race's next attempt is due at `at`: its timer armed for then, or
/// for the end of the time left to connect if that comes first, as C
/// arms it.
fn eyeballs_due<H: Host>(run: &mut Run, cx: &mut StepCx<'_, H>, at: Instant) {
    // The time read again, after the attempts' work (`cf_ip_ballers_run`).
    let now = cx.rest.clock.now();
    let mut wait = wait_ms(now, at);
    if let TimeLeft::Remaining(left) = run.deadlines.time_left(starts(cx), now, Phase::Connecting) {
        wait = wait.min(left);
    }
    let ms = wait.as_millis();
    let he = Component::HappyEyeballs;
    trace::of(
        cx,
        he,
        format_args!("next HAPPY_EYEBALLS timeout in {ms}ms"),
    );
    let at = run.deadlines.arm_in(TimerKind::Eyeballs, now, wait);
    trace_set(cx, TimerKind::Eyeballs, at);
}

/// The race's attempt to `remote`, the peer `route` connects to first
/// or the proxy a handshake goes through, connected: the race is over,
/// and counted (`cf_ip_happy_connect`).
fn eyeballs_won<H: Host>(cx: &mut StepCx<'_, H>, route: &NetRoute, remote: &Remote) {
    said_won(cx, route, remote);
    cx.report_mut().count_connect();
}

/// A race's attempt to `remote` connected, said as C says it.
fn said_won<H: Host>(cx: &mut StepCx<'_, H>, route: &NetRoute, remote: &Remote) {
    let he = Component::HappyEyeballs;
    let (name, ip, port) = (route.destination().name(), remote.shown_ip(), remote.port());
    let port = Text::<16>::clipped(format_args!(") port {port}")).0;
    trace::of_with(
        cx,
        he,
        &[b"Connected to ", name, b" (", ip.bytes(), port.bytes()],
    );
    trace_timer(cx, TimerKind::Eyeballs, format_args!("cleared"));
}

/// The QUIC library's timer armed to fire `wait` (`Curl_expire_set(EXPIRE_QUIC)`)
/// from the time read again, as C arms it from the time its filter read.
pub(crate) fn arm_quic<H: Host>(deadlines: &mut Deadlines, cx: &mut StepCx<'_, H>, wait: Duration) {
    let now = cx.rest.clock.now();
    let at = deadlines.arm_in(TimerKind::Quic, now, wait);
    trace_set(cx, TimerKind::Quic, at);
}

/// Arm `kind` to fire `wait` after the step's start, traced as C's
/// `Curl_expire_set` traces it.
pub(super) fn arm<H: Host>(
    deadlines: &mut Deadlines,
    cx: &mut StepCx<'_, H>,
    kind: TimerKind,
    wait: Duration,
) {
    let at = deadlines.arm_in(kind, cx.now(), wait);
    trace_set(cx, kind, at);
}

/// `kind` was armed to fire at `at`: what is left of its wait as it is
/// traced, read from the clock again as C reads it (`multi_set_timeout`).
pub(crate) fn trace_set<H: Host>(cx: &mut StepCx<'_, H>, kind: TimerKind, at: Instant) {
    if trace::traces(cx, Component::Timer) {
        let left = at.since(cx.rest.clock.now()).as_micros();
        trace_timer(cx, kind, format_args!("set for {left}us"));
    }
}

/// A line of the timer component's about `kind` (`CURL_TRC_TIMER`).
pub(crate) fn trace_timer<H: Host>(
    cx: &mut StepCx<'_, H>,
    kind: TimerKind,
    args: fmt::Arguments<'_>,
) {
    let name = kind.name();
    trace::of(cx, Component::Timer, format_args!("[{name}] {args}"));
}

/// A setup failed with its first hop connected: the transfer keeps the
/// connection's ends and when it connected (`Curl_conn_report_failed`).
fn report_failed<H: Host>(
    cx: &mut StepCx<'_, H>,
    partly: Option<(Remote, Option<SocketAddr>, Instant)>,
) {
    let Some((remote, local, at)) = partly else {
        return;
    };
    cx.report_mut().set_primary(Ends { remote, local });
    let marked = cx.report_mut().timings_mut().mark(Timer::Connect, at);
    mstate::marked(cx, Timer::Connect, marked);
}

/// The connection is set up (`conn_connect_trace`): timed and traced;
/// `preface` if the PROXY protocol's line was sent over it.
pub(super) fn up<H: Host>(
    mut c: Connecting,
    cx: &mut StepCx<'_, H>,
    remote: Remote,
    local: Option<SocketAddr>,
    at: Instant,
    preface: bool,
    lost: Option<ConnectMachine>,
) -> (TransferState, Wake) {
    // What its tunnel negotiated is the connection's from now on.
    *c.lease.get().negotiate_mut() = c.negotiate.take();
    let mut head = head_of(&c);
    if c.https.is_some() {
        // The winner's chain is asked whether HTTP/2 was agreed
        // (`baller_connected`), from its SETUP filter: if it was, the
        // HTTP/2 filter goes in below the HTTPS connect filter and is
        // connected there and then (`Curl_http2_switch_at`).
        let alpn = query_alpn(cx, c.lease.query(LayerQuery::Alpn), Component::Setup);
        if alpn == Some(crate::tls::Chosen::H2) && cx.easy().libraries().h2.is_some() {
            if let Err(kind) = crate::proto::http::open_session(cx, &mut c.lease) {
                https::call_ended(c.https, cx, Err(kind));
                chain_connect_ended(cx, Err(kind));
                return (TransferState::Connecting(c).fail(kind), Wake::Again);
            }
            head.h2 = true;
        }
    }
    https::call_ended(c.https, cx, Ok(true));
    let route = c.lease.conn().dialing().expect("set up over the network");
    let target = crate::conn::chain::resolves_target(route.route);
    names::connected(cx, ConnRank::First, target, head.record);
    chain_connect_ended(cx, Ok(true));
    // Its TLS is up now, and its socket was when it connected
    // (`Curl_pgrsTime` for `TIMER_APPCONNECT` as the SSL filter connects),
    // unless its handshake is put off for early data, which times it as
    // it ends (`early_done`).
    // A QUIC connection reports its own: connected as its first datagram
    // came, then up as its handshake completed (`Curl_cf_ngtcp2_cmn_cntrl`).
    // Through an HTTP/3 proxy, no filter of the chain reports the connect:
    // the proxy's QUIC connection keeps its socket to itself, its filter
    // reports nothing, and a QUIC origin over its tunnel has no socket of
    // its own (`Curl_cf_ngtcp2_cmn_cntrl`), so C's time is never set.
    let timed = !c.route.proxy_over_quic();
    let handshake_at = c.lease.conn().h3().and_then(|h3| h3.handshake_at());
    if let Some(handshake_at) = handshake_at {
        if timed {
            let marked = cx.report_mut().timings_mut().mark(Timer::Connect, at);
            mstate::marked(cx, Timer::Connect, marked);
        }
        let marked = cx
            .report_mut()
            .timings_mut()
            .mark(Timer::AppConnect, handshake_at);
        mstate::marked(cx, Timer::AppConnect, marked);
    } else {
        if c.route.tls.is_some() && c.lease.query(LayerQuery::TlsDeferred).is_none() {
            let now = cx.now();
            let marked = cx.report_mut().timings_mut().mark(Timer::AppConnect, now);
            mstate::marked(cx, Timer::AppConnect, marked);
        }
        if timed {
            let marked = cx.report_mut().timings_mut().mark(Timer::Connect, at);
            mstate::marked(cx, Timer::Connect, marked);
        }
    }
    // `CURL_CONN_HOST_DISPNAME`.
    say_established(cx, c.route.destination().shown(), &remote, local);
    cx.report_mut().set_primary(Ends { remote, local });
    // The setup filters go once the chain is connected
    // (`Curl_conn_remove_setup_filters`).
    let tunnel = c
        .lease
        .query(LayerQuery::Tunnel)
        .map_or(Component::H1Proxy, |a| match a {
            LayerAnswer::Tunnel(filter) => filter,
            _ => unreachable!("an answer of another question"),
        });
    // The route the winner dialed, which a race's second dials
    // otherwise than the plan's.
    let route = c.lease.conn().dialing().expect("set up over the network");
    let connected = Chain::connected(route, head, preface, tunnel);
    mstate::trace(cx, format_args!("connected {connected}"));
    // The race's loser goes with the HTTPS connect filter, its chain from
    // its setup filter down (`cf_hc_ctx_destroy`).
    let race = c.race.take();
    // A first attempt that failed keeps its setup's filters, its
    // attempts gone as they failed, until then.
    let first_failed = race.as_ref().is_some_and(|r| r.first_failed.is_some());
    assert!(
        race.as_ref().is_none_or(|r| r.second.running().is_none()),
        "the race's loser is given"
    );
    // One that failed once dialed goes with its connection.
    let mut kept = race.and_then(|r| r.failed.or(r.second.into_machine()));
    let mut lost = lost;
    // Each DNS filter lets go of the entry it holds as it goes, the race's
    // above both its attempts.
    let dns = names::filters(ConnRank::First, target, head.record);
    names::setup_filters_go(cx, &connected, ConnRank::First, dns, |cx, filter| {
        if filter != Component::HttpsConnect {
            return;
        }
        if let Some(lost) = lost.take() {
            trace::of(cx, Component::Setup, format_args!("destroy"));
            lost.discard(&mut DriveCx::new(cx, None));
        } else if let Some(failed) = kept.take() {
            trace::of(cx, Component::Setup, format_args!("destroy"));
            failed.lose(&mut DriveCx::new(cx, None));
        } else if first_failed {
            trace::of(cx, Component::Setup, format_args!("destroy"));
            trace::of(cx, Component::HappyEyeballs, format_args!("destroy"));
        }
    });
    assert!(lost.is_none(), "the HTTPS connect filter goes");
    let reduced = connected.reduced();
    mstate::trace(cx, format_args!("reduced to {reduced}"));
    // A new connection that multiplexes lets one waiting look again
    // before the transfer goes on (`multi_connecting`).
    if c.lease.multiplexes() {
        schedule_pending(&mut cx.rest);
    }
    (c.attached(), Wake::Again)
}

/// The connection to `host` is connected all the way, from `local` to
/// `remote`, said as C says it each time its whole chain is
/// (`conn_connect_trace`).
pub(crate) fn say_established<H: Host>(
    cx: &mut StepCx<'_, H>,
    host: &[u8],
    remote: &Remote,
    local: Option<SocketAddr>,
) {
    let (lip, lport) = local.map_or((None, 0), |l| (Some(l.ip()), l.port()));
    let lip = Ip(lip);
    let mut line = trace::Line::new();
    line.raw(b"Established connection to ").raw(host).raw(b" (");
    line.raw(remote.shown_ip().bytes());
    line.text(format_args!(
        " port {}) from {lip} port {lport} ",
        remote.port()
    ));
    trace::info_with(cx, &[line.bytes()]);
}

/// Why the setup failed, as C traces it (`cf_tcp_connect`,
/// `is_connected`).
pub(crate) fn connect_failed<H: Host>(
    cx: &mut StepCx<'_, H>,
    route: &NetRoute,
    e: ConnectError,
) -> ErrorKind {
    // The peer connected to: the first proxy, else what a connect-to
    // names in the origin's place, else the origin
    // (`Curl_conn_get_first_peer`).
    let first = route.destination();
    // The proxy named in a failure: the SOCKS one when there are two
    // (`socks_proxy` before `http_proxy`), which is the first.
    let proxy = route.proxy.as_ref().map(ProxyRoute::first_peer);
    let failure = match e {
        ConnectError::OutOfMemory => return ErrorKind::OutOfMemory,
        ConnectError::Aborted => return ErrorKind::AbortedByCallback,
        ConnectError::Refused(kind) => return kind,
        ConnectError::Unresolved(why) => {
            match why {
                Unresolved::GaveUp => unreachable!("said of a blocking resolve, to its caller"),
                Unresolved::NoIpv6 => return no_ipv6(cx, route, proxy.is_some()),
                Unresolved::DebugFailIpv6 => return debug_failed_ipv6(cx, route, proxy.is_some()),
                Unresolved::UnixPathTooLong => {
                    // `resolv_unix`, then the name's filter, which says
                    // the path alone.
                    let path = first.name();
                    let kind = ErrorKind::CouldntResolveHost;
                    let kind =
                        trace::fail_with(cx, kind, &[b"Unix socket path too long: '", path, b"'"]);
                    trace::info_with(cx, &[b"Could not resolve: ", path]);
                    return kind;
                }
                Unresolved::Onion => {
                    let (onion, at) = (first.name(), port_text(first.port()));
                    let kind = match proxy {
                        Some(_) => ErrorKind::CouldntResolveProxy,
                        None => ErrorKind::CouldntResolveHost,
                    };
                    let why = format_args!("Not resolving .onion address (RFC 7686)");
                    let kind = trace::fail(cx, kind, why);
                    trace::info_with(cx, &[b"Could not resolve: ", onion, at.bytes()]);
                    trace::info_with(cx, &[b"Could not resolve: ", onion]);
                    return kind;
                }
                Unresolved::Negative => trace_lookup(cx, route, None),
                Unresolved::NegativeMeanwhile
                | Unresolved::Resolver {
                    says_its_own: true, ..
                } => {}
                Unresolved::Resolver { queued, .. } => {
                    // A setup's resolve that queued its queries said its
                    // own lines as they were answered (`says_its_own`).
                    assert!(queued.is_none(), "a queued resolve says its own lines");
                    trace_lookup(cx, route, Some(Found::Resolved(Asked::Resolver(None))));
                    trace_resolved(cx, route, None, None);
                }
                Unresolved::NoAddress(found) => {
                    trace_lookup(cx, route, Some(found));
                    if let Found::Stale(asked) | Found::Resolved(asked) = found {
                        trace_resolved(cx, route, Some(asked), None);
                    }
                }
            }
            // The name looked up is the first peer's: with a proxy, the
            // first proxy's.
            let (host, at) = (first.name(), port_text(first.port()));
            let at = at.bytes();
            let (what, kind): (&[u8], _) = match proxy {
                Some(_) => (b"Could not resolve proxy: ", ErrorKind::CouldntResolveProxy),
                None => (b"Could not resolve host: ", ErrorKind::CouldntResolveHost),
            };
            if why == Unresolved::Negative {
                trace::info(cx, format_args!("Negative DNS entry"));
            }
            let kind = match why {
                // The resolver says so as it answers, with its reason if
                // it gives one, as the reference build's c-ares does
                // (`ares_strerror`), and the lookup again without
                // (`Curl_async_failed`, twice).
                Unresolved::Resolver {
                    explained,
                    over_doh: false,
                    library_status,
                    ..
                } => {
                    let kind = match explained {
                        Some(reason) => trace::fail_with(
                            cx,
                            kind,
                            &[what, host, b" (", reason.as_bytes(), b")"],
                        ),
                        None => trace::fail_with(cx, kind, &[what, host]),
                    };
                    if let Some(status) = library_status {
                        let queries = queries(first, route.ip, cx.rest.ipv6_works);
                        let code = trace::Code(Err(kind));
                        trace::of(
                            cx,
                            Component::Dns,
                            format_args!(
                                "[{queries}] ares_take_result, result={code}, ares_result=0, \
                                 ares_status={status}, dns=not found"
                            ),
                        );
                    }
                    trace::fail_with(cx, kind, &[what, host])
                }
                _ => trace::fail_with(cx, kind, &[what, host]),
            };
            // Failed inside its start, the resolve's record goes, and the
            // start says it is done (`hostip_resolv_start`'s
            // `Curl_async_destroy`, `hostip_resolv`).
            if let Unresolved::Resolver {
                in_start: Some(holder),
                ..
            } = why
            {
                super::names::async_gone(cx, holder);
                let queries = queries(first, route.ip, cx.rest.ipv6_works);
                let code = trace::Code(Err(kind));
                trace::of(
                    cx,
                    Component::Dns,
                    format_args!("[{queries}] hostip_resolv started -> {code}"),
                );
            }
            // What the resolver said no to is kept as said
            // (`Curl_dnscache_add_negative`).
            if let Unresolved::Resolver {
                why: ResolveFailure::NotFound | ResolveFailure::NoData,
                ..
            } = why
            {
                let queries = queries(first, route.ip, cx.rest.ipv6_works);
                trace::of_with(
                    cx,
                    Component::Dns,
                    &[
                        b"cache negative name resolve for ",
                        host,
                        at,
                        b" type=",
                        queries.as_bytes(),
                    ],
                );
            }
            // Said once, by the resolve, and only that it failed
            // (`Curl_async_failed`).
            if why == Unresolved::NegativeMeanwhile {
                let queries = queries(first, route.ip, cx.rest.ipv6_works);
                let code = trace::Code(Err(kind));
                trace::of(
                    cx,
                    Component::Dns,
                    format_args!("[{queries}] error resolving: {code}"),
                );
                return kind;
            }
            trace::info_with(cx, &[b"Could not resolve: ", host, at]);
            // The name's filter says so of any resolver's failure
            // (`cf_dns_connect`).
            if let Unresolved::Resolver {
                over_doh: false,
                in_start,
                ..
            } = why
            {
                // A start that failed says so itself (`cf_dns_start`).
                if in_start.is_some() {
                    trace::info_with(cx, &[b"Could not resolve: ", host]);
                }
                let queries = queries(first, route.ip, cx.rest.ipv6_works);
                let code = trace::Code(Err(kind));
                trace::of(
                    cx,
                    Component::Dns,
                    format_args!("[{queries}] error resolving: {code}"),
                );
            }
            if why == Unresolved::Negative {
                trace::info_with(cx, &[b"Could not resolve: ", host]);
                let queries = queries(first, route.ip, cx.rest.ipv6_works);
                let code = trace::Code(Err(kind));
                trace::of(
                    cx,
                    Component::Dns,
                    format_args!("[{queries}] error resolving: {code}"),
                );
            }
            return kind;
        }
        ConnectError::Failed(_, kind) => {
            // The drive traced the failure, and kept its number.
            // No attempt running, and no address left: what the attempts
            // said is let go as the race looks for another
            // (`cf_ip_ballers_run`).
            trace::reset_fail(cx);
            trace::of(
                cx,
                Component::HappyEyeballs,
                format_args!("no more attempts to try"),
            );
            kind
        }
    };
    let origin = &*route.origin;
    let mut line = trace::Line::new();
    line.raw(b"Failed to connect to ").raw(origin.name());
    line.text(format_args!(":{}", origin.port()));
    // A peer that is neither the origin nor the proxy named is shown.
    match Some(first).filter(|&f| f != origin && Some(f) != proxy) {
        Some(via) if via.is_unix() => {
            line.raw(b" over unix://").raw(via.name());
        }
        Some(via) => {
            line.raw(b" via ").raw(via.name());
            line.text(format_args!(":{}", via.port()));
        }
        None => {}
    }
    line.raw(b" ");
    // The proxy connected through.
    if let Some(proxy) = proxy {
        line.raw(b"over proxy ").raw(proxy.name()).raw(b" ");
    }
    // Read from the clock now, as `Curl_pgrs_now` reads it: a blocking
    // resolve may have waited inside this step.
    let now = cx.rest.clock.now();
    let ms = cx.easy().report().timings().since_single_ms(now);
    // The last attempt's failure says what the setup's is.
    let why = failure.message();
    line.text(format_args!("after {ms} ms: {why}"));
    trace::fail_with(cx, failure, &[line.bytes()])
}

/// The addresses a name resolved to, each family on a line of its own
/// (`cf_dns_report`), under the name it was found for; nothing for an
/// address the URL names.
fn report_answer<H: Host>(cx: &mut StepCx<'_, H>, c: &Connecting) {
    let Some(answer) = c.lead().and_then(|m| m.answer().cloned()) else {
        return;
    };
    report_resolved(cx, &answer, c.route.destination().port());
}

/// As `report_answer`, for `answer`, found for port `port`.
pub(super) fn report_resolved<H: Host>(cx: &mut StepCx<'_, H>, answer: &Answer, port: u16) {
    if !answer.resolved() {
        return;
    }
    let at = port_text(port);
    trace::info_with(
        cx,
        &[b"Host ", answer.name(), at.bytes(), b" was resolved."],
    );
    trace::info(
        cx,
        format_args!("IPv6: {}", crate::conn::OfFamily(answer.addrs(), true)),
    );
    trace::info(
        cx,
        format_args!("IPv4: {}", crate::conn::OfFamily(answer.addrs(), false)),
    );
}

/// The request ran out of time, with what it received of how much if
/// its protocol `sized` it, and the time since its own start while it was
/// `Connecting`, since the transfer's first request's after
/// (`multi_handle_timeout`: from `TIMER_STARTSINGLE` while
/// `Curl_is_connecting`, else `TIMER_STARTOP`; `req.size`).
pub(super) fn timed_out<H: Host>(cx: &mut StepCx<'_, H>, phase: Phase, sized: bool) -> ErrorKind {
    let timings = cx.easy().report().timings();
    let ms = match phase {
        Phase::Connecting => timings.since_single_ms(cx.rest.now),
        Phase::Transferring => timings.since_op_ms(cx.rest.now),
    };
    let report = cx.easy().report();
    let sizes = report.sizes();
    let got = sizes.download();
    let kind = ErrorKind::OperationTimedout;
    match sizes.download_expected().filter(|_| sized) {
        Some(size) => trace::fail(
            cx,
            kind,
            format_args!(
                "Operation timed out after {ms} milliseconds with {got} out of {size} bytes received"
            ),
        ),
        None => trace::fail(
            cx,
            kind,
            format_args!("Operation timed out after {ms} milliseconds with {got} bytes received"),
        ),
    }
}
