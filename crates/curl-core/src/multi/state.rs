//! A transfer's states and the steps between them (`multi_runsingle`).
//!
//! The variants hold what is valid in them: a connection lease exists from
//! the moment a transfer has a connection until `Done` gives it back, and
//! only `Done` gives it back.

use std::fmt::Write as _;
use std::net::{IpAddr, SocketAddr};

use curl_alloc::{OutOfMemory, TryVec};

use crate::conn::io::{Events, Socket};
use crate::conn::{
    Acquired, Conn, ConnLease, ConnectError, Connected, Destination, Finish, Pool, PoolNote,
    Progress, Released, ReuseRules, Route,
};
use crate::deliver::{Directions, Pause, PauseRequest, Pipeline, RecvPause};
use crate::easy::Easy;
use crate::error::{ErrorKind, UrlErrorKind};
use crate::options::Options;
use crate::progress::{self, Speedometer};
use crate::proto::{ProtoState, ProtoStep};
use crate::report::{Timer, TransferReport};
use crate::text::Text;
use crate::time::{Instant, TimeLimit};
use crate::trace;
use crate::url::{self, GetOptions, ParseOptions, Part, Url};
use crate::version::Protocol;

use super::cx::{EngineRest, TransferCalls};
use super::timers::{Deadlines, Phase, TimeLeft, TimerKind};
use super::{Host, TransferId};

/// A transfer from `add` to `remove`.
#[derive(Debug)]
pub(crate) struct Run {
    pub(crate) state: TransferState,
    pub(crate) deadlines: Deadlines,
    /// The first transfer added to its multi says that the library is a
    /// debug build (`multi_warn_debug`).
    #[cfg(feature = "debug-hooks")]
    pub(crate) warn: bool,
}

impl Run {
    pub(crate) fn new(now: Instant) -> Run {
        Run {
            state: TransferState::Init,
            deadlines: Deadlines::new(now, None, None),
            #[cfg(feature = "debug-hooks")]
            warn: false,
        }
    }
}

#[derive(Debug)]
pub(crate) enum TransferState {
    /// Added, not yet run.
    Init,
    /// Holding a connection being set up (C's CONNECTING).
    Connecting(Connecting),
    /// Holding a connection, the protocol connecting over it (C's
    /// PROTOCONNECT).
    ProtoConnect(Attached),
    /// Making its request (DO).
    Do(Attached),
    /// The request is made (DID).
    Did(Attached),
    /// The request and response under way (PERFORMING).
    Exchanging(Attached),
    /// The request is over; the connection goes back at the next step.
    Done(Done),
    /// Over; its message is read or not. Terminal until removed.
    Completed(Completed),
}

/// A request whose connection is being set up.
#[derive(Debug)]
pub(crate) struct Connecting {
    lease: ConnLease,
    proto: ProtoState,
    /// The host and port connected to, as the failure names them.
    origin: Origin,
}

/// The host a request is for, as the URL holds it, and its port (C's
/// `conn->origin`).
#[derive(Debug)]
struct Origin {
    host: Vec<u8>,
    port: u16,
}

impl Origin {
    /// The host as the URL names it, an IPv6 address in brackets (C's
    /// `user_hostname`).
    fn shown(&self) -> Bytes<'_> {
        Bytes(&self.host)
    }

    /// The host without the brackets of an IPv6 address (C's
    /// `hostname`).
    fn name(&self) -> Bytes<'_> {
        let h = &self.host;
        Bytes(
            h.strip_prefix(b"[")
                .and_then(|h| h.strip_suffix(b"]"))
                .unwrap_or(h),
        )
    }
}

/// A request holding its connection.
#[derive(Debug)]
pub(crate) struct Attached {
    lease: ConnLease,
    proto: ProtoState,
    /// The host connected to; none without a network.
    origin: Option<Origin>,
}

#[derive(Debug)]
pub(crate) struct Done {
    lease: ConnLease,
    /// The protocol, to say its last of the request; none if it never
    /// connected over the connection.
    proto: Option<ProtoState>,
    result: Result<(), ErrorKind>,
    /// Ended before the request was complete.
    premature: bool,
    reached: Reached,
    /// The host connected to, if any, as a connection kept names it.
    origin: Option<Origin>,
}

/// How far a request got.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Reached {
    /// It was not made: DID's times are not taken.
    Unmade,
    /// It was made; any exchange after did not run to its end.
    Made,
    /// Its exchange ran to its end (C's `req.done`): the last progress
    /// pass shows the meter however soon it comes.
    Exchanged,
}

#[derive(Debug)]
pub(crate) struct Completed {
    pub(crate) outcome: Result<(), ErrorKind>,
    pub(crate) message: Message,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Message {
    Unread,
    Read,
}

/// Whether to step a transfer again in the same pass.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Wake {
    Again,
    Idle,
}

impl TransferState {
    /// Whether the transfer holds a connection lease.
    pub(crate) fn holds_lease(&self) -> bool {
        self.attached().is_some()
            || matches!(self, TransferState::Connecting(_) | TransferState::Done(_))
    }

    fn attached(&self) -> Option<&Attached> {
        match self {
            TransferState::ProtoConnect(x)
            | TransferState::Do(x)
            | TransferState::Did(x)
            | TransferState::Exchanging(x) => Some(x),
            _ => None,
        }
    }

    fn attached_mut(&mut self) -> Option<&mut Attached> {
        match self {
            TransferState::ProtoConnect(x)
            | TransferState::Do(x)
            | TransferState::Did(x)
            | TransferState::Exchanging(x) => Some(x),
            _ => None,
        }
    }

    /// The output of the request under way, if its protocol delivers any.
    pub(crate) fn pipeline_mut(&mut self) -> Option<&mut Pipeline> {
        self.attached_mut()?.proto.pipeline_mut()
    }

    /// Whether the request under way holds output for the application.
    #[cfg(debug_assertions)]
    pub(crate) fn holds_output(&self) -> bool {
        self.attached().is_some_and(|x| x.proto.holds_output())
    }

    pub(crate) fn is_completed(&self) -> bool {
        matches!(self, TransferState::Completed(_))
    }

    /// End the transfer with `err`: through `Done` if it holds a
    /// connection, straight to `Completed` if not. A transfer already
    /// finishing keeps its result, as `multi_done` runs once.
    pub(crate) fn fail(self, err: ErrorKind) -> TransferState {
        match self {
            TransferState::Init => TransferState::Completed(Completed {
                outcome: Err(err),
                message: Message::Unread,
            }),
            TransferState::Connecting(c) => TransferState::Done(Done {
                lease: c.lease,
                proto: None,
                result: Err(err),
                premature: true,
                reached: Reached::Unmade,
                origin: Some(c.origin),
            }),
            TransferState::ProtoConnect(x) | TransferState::Do(x) => {
                TransferState::Done(x.done(Err(err), true, Reached::Unmade))
            }
            TransferState::Did(x) | TransferState::Exchanging(x) => {
                TransferState::Done(x.done(Err(err), true, Reached::Made))
            }
            s @ (TransferState::Done(_) | TransferState::Completed(_)) => s,
        }
    }

    /// Take the transfer out of the multi before it completed: give back
    /// its connection, as a premature end (`curl_multi_remove_handle`).
    pub(crate) fn abandon<H: Host>(self, cx: &mut StepCx<'_, H>) {
        let (lease, origin) = match self {
            TransferState::Init | TransferState::Completed(_) => return,
            TransferState::Connecting(c) => (c.lease, Some(c.origin)),
            TransferState::ProtoConnect(x)
            | TransferState::Do(x)
            | TransferState::Did(x)
            | TransferState::Exchanging(x) => (x.lease, x.origin),
            TransferState::Done(d) => (d.lease, d.origin),
        };
        release(cx, lease, Finish { premature: true }, origin.as_ref());
    }
}

/// Give the transfer's connection back, and trace its fate
/// (`Curl_cpool_return`, `cpool_conn_close`).
fn release<H: Host>(
    cx: &mut StepCx<'_, H>,
    lease: ConnLease,
    finish: Finish,
    origin: Option<&Origin>,
) {
    let now = cx.rest.now;
    let (pool, mut net) = cx.rest.pool_net(cx.me);
    match pool.release(lease, finish, &mut net, now) {
        Released::Idle(n) => {
            let origin = origin.expect("a connection kept has a host");
            let (host, port) = (origin.shown(), origin.port);
            trace::info(
                cx,
                format_args!("Connection {n} to host {host}:{port} left intact"),
            );
        }
        Released::Closed(n) => trace::info(cx, format_args!("shutting down connection {n}")),
        Released::Terminated(n) => trace::info(cx, format_args!("closing connection {n}")),
    }
}

impl TransferState {
    /// The socket the transfer waits on, and for what (`Curl_multi_pollset`):
    /// a setup waits to write, unless receiving is paused
    /// (`mstate_connecting_pollset`); an exchange waits for what its
    /// protocol says (`Curl_http_perform_pollset`).
    pub(crate) fn pollset<'p>(
        &self,
        pool: &'p Pool,
        pause: Pause,
    ) -> Option<(&'p dyn Socket, Events)> {
        match self {
            TransferState::Connecting(c) if pause.recv == RecvPause::Running => {
                pool.socket(&c.lease).map(|s| (s, Events::OUT))
            }
            TransferState::Exchanging(x) => {
                let events = x.proto.interest(pause);
                pool.socket(&x.lease)
                    .filter(|_| !events.is_empty())
                    .map(|s| (s, events))
            }
            _ => None,
        }
    }
}

impl Connecting {
    /// The connection is up: on to the protocol's connect.
    fn attached(self) -> TransferState {
        let Connecting {
            lease,
            proto,
            origin,
        } = self;
        TransferState::ProtoConnect(Attached {
            lease,
            proto,
            origin: Some(origin),
        })
    }
}

impl Attached {
    fn done(self, result: Result<(), ErrorKind>, premature: bool, reached: Reached) -> Done {
        Done {
            lease: self.lease,
            proto: Some(self.proto),
            result,
            premature,
            reached,
            origin: self.origin,
        }
    }
}

/// What a step needs: the transfer it steps, whose `Run` is out of its
/// slot, and the rest of the multi.
pub(crate) struct StepCx<'a, H: Host> {
    pub(crate) me: TransferId,
    pub(super) rest: EngineRest<'a, H>,
}

impl<H: Host> StepCx<'_, H> {
    pub(crate) fn easy(&self) -> &Easy {
        &self
            .rest
            .slots
            .get(self.me)
            .expect("the stepping transfer")
            .easy
    }
}

impl<H: Host> StepCx<'_, H> {
    /// The connection `lease` holds.
    pub(crate) fn conn(&mut self, lease: &ConnLease) -> &mut Conn {
        self.rest.pool.get(lease)
    }

    pub(crate) fn report_mut(&mut self) -> &mut TransferReport {
        self.rest
            .slots
            .get_mut(self.me)
            .expect("the stepping transfer")
            .easy
            .report_mut()
    }

    pub(crate) fn pause(&self) -> Pause {
        self.rest
            .slots
            .get(self.me)
            .expect("the stepping transfer")
            .pause
    }

    pub(crate) fn directions_mut(&mut self) -> &mut Directions {
        &mut self
            .rest
            .slots
            .get_mut(self.me)
            .expect("the stepping transfer")
            .directions
    }

    pub(crate) fn pause_mut(&mut self) -> &mut Pause {
        &mut self
            .rest
            .slots
            .get_mut(self.me)
            .expect("the stepping transfer")
            .pause
    }

    pub(crate) fn now(&self) -> Instant {
        self.rest.now
    }

    pub(crate) fn easy_mut(&mut self) -> &mut Easy {
        &mut self
            .rest
            .slots
            .get_mut(self.me)
            .expect("the stepping transfer")
            .easy
    }

    pub(crate) fn speedometer_mut(&mut self) -> &mut Speedometer {
        &mut self
            .rest
            .slots
            .get_mut(self.me)
            .expect("the stepping transfer")
            .speedometer
    }

    /// The speedometer and the report it writes to.
    pub(crate) fn progress_parts(&mut self) -> (&mut Speedometer, &mut TransferReport) {
        let slot = self
            .rest
            .slots
            .get_mut(self.me)
            .expect("the stepping transfer");
        (&mut slot.speedometer, slot.easy.report_mut())
    }

    pub(crate) fn mark(&mut self, timer: Timer) {
        let now = self.rest.now;
        self.report_mut().timings_mut().mark(timer, now);
    }
}

impl<H: Host> TransferCalls for StepCx<'_, H> {
    fn me(&self) -> TransferId {
        self.me
    }

    fn easy(&self, id: TransferId) -> Option<&Easy> {
        self.rest.slots.get(id).map(|s| &s.easy)
    }

    fn easy_mut(&mut self, id: TransferId) -> Option<&mut Easy> {
        self.rest.slots.get_mut(id).map(|s| &mut s.easy)
    }

    fn pause(&mut self, id: TransferId, req: PauseRequest) -> Result<(), ErrorKind> {
        super::pause_transfer(&mut self.rest, id, req)
    }

    fn fail(&mut self, why: &[u8]) {
        // The kind is the verdict's to decide.
        trace::fail_with(self, ErrorKind::WriteError, &[why]);
    }
}

/// Replay a transfer's held output, from outside its step.
pub(crate) fn flush<H: Host>(run: &mut Run, cx: &mut StepCx<'_, H>) -> Result<(), ErrorKind> {
    match run.state.pipeline_mut() {
        Some(p) => p.flush(cx),
        None => Ok(()),
    }
}

/// Run one step of `run`.
pub(crate) fn step<H: Host>(run: &mut Run, cx: &mut StepCx<'_, H>) -> Wake {
    let state = std::mem::replace(&mut run.state, TransferState::Init);
    let (next, wake) = match state {
        TransferState::Init => {
            let limits = cx.easy().options().limits;
            run.deadlines = Deadlines::new(cx.rest.now, limits.total, limits.connect);
            let now = cx.rest.now;
            cx.report_mut().restart(now);
            *cx.speedometer_mut() = Speedometer::default();
            let next = setup(run, cx);
            if next.is_completed() {
                enter_completed(cx.report_mut(), now, true);
            }
            (next, Wake::Again)
        }
        TransferState::Connecting(c) => connecting(run, c, cx),
        // No protocol connects over its connection yet.
        TransferState::ProtoConnect(x) => (TransferState::Do(x), Wake::Again),
        TransferState::Do(mut x) => match x.proto.do_it(cx, &x.lease) {
            Ok(()) => {
                // About to send; sent already, with no body
                // (`mstate_enter_did`).
                cx.mark(Timer::PreTransfer);
                let send = x.proto.wants_send(cx.easy().options());
                if !send {
                    cx.mark(Timer::PostTransfer);
                }
                // The ways it moves bytes from here (`xfer_setup`).
                *cx.directions_mut() = Directions {
                    recv: x.proto.exchanges(),
                    send,
                };
                (TransferState::Did(x), Wake::Again)
            }
            // A failed request is done with, not cut short (`multistate_do`).
            Err(e) => (
                TransferState::Done(x.done(Err(e), false, Reached::Unmade)),
                Wake::Again,
            ),
        },
        // Without anything to exchange, the request is over
        // (`multistate_did`).
        TransferState::Did(x) if !x.proto.exchanges() => (
            TransferState::Done(x.done(Ok(()), false, Reached::Made)),
            Wake::Again,
        ),
        TransferState::Did(x) => (TransferState::Exchanging(x), Wake::Again),
        TransferState::Exchanging(mut x) => {
            let stepped = x.proto.step(cx, &x.lease);
            let expired = matches!(
                run.deadlines.time_left(cx.rest.now, Phase::Transferring),
                TimeLeft::Expired(_)
            );
            match stepped {
                Err(e) => (TransferState::Exchanging(x).fail(e), Wake::Again),
                // Out of time at the end of the pass (transfer.c:382).
                Ok(ProtoStep::Blocked) if expired => {
                    let kind = timed_out(cx);
                    (TransferState::Exchanging(x).fail(kind), Wake::Again)
                }
                Ok(stepped) => {
                    // The end of a receive pass (`Curl_sendrecv`).
                    let done = stepped == ProtoStep::Done;
                    match progress::check(cx, done) {
                        Err(e) => (TransferState::Exchanging(x).fail(e), Wake::Again),
                        Ok(look_again) => {
                            if let Some(wait) = look_again {
                                run.deadlines.arm_in(TimerKind::SpeedCheck, cx.now(), wait);
                            }
                            if done {
                                (
                                    TransferState::Done(x.done(Ok(()), false, Reached::Exchanged)),
                                    Wake::Again,
                                )
                            } else {
                                (TransferState::Exchanging(x), Wake::Idle)
                            }
                        }
                    }
                }
            }
        }
        TransferState::Done(mut d) => {
            // Whether the request was cut short is decided by how it
            // ended, not by the protocol's last word (`multi_done`), which
            // comes first.
            let mut premature = d.premature || is_premature(d.result);
            if let Some(proto) = d.proto.as_mut() {
                d.result = proto.done(cx, &d.lease, d.result, premature);
            }
            // A last progress pass, unless a callback aborted already.
            if d.result != Err(ErrorKind::AbortedByCallback)
                && let Err(e) = progress::finish(cx, d.reached == Reached::Exchanged)
                && d.result.is_ok()
            {
                d.result = Err(e);
                premature |= is_premature(d.result);
            }
            release(cx, d.lease, Finish { premature }, d.origin.as_ref());
            // The request moves nothing more (`Curl_req_stop_send_recv`).
            *cx.directions_mut() = Directions::default();
            // Held output went with the request; a pause the application
            // asked for stays.
            let pause = cx.pause_mut();
            if pause.recv == RecvPause::Held {
                pause.recv = RecvPause::Running;
            }
            let completed = TransferState::Completed(Completed {
                outcome: d.result,
                message: Message::Unread,
            });
            let now = cx.rest.now;
            enter_completed(cx.report_mut(), now, d.reached == Reached::Unmade);
            (completed, Wake::Again)
        }
        s @ TransferState::Completed(_) => (s, Wake::Idle),
    };
    let (next, wake) = progress_after_step(next, wake, cx);
    run.state = next;
    wake
}

/// A step that went well, with a connection, ends with a progress pass
/// (the tail of `multi_runsingle`'s loop, after `is_finished`). The
/// handler may have unpaused held output: it is replayed at once.
fn progress_after_step<H: Host>(
    next: TransferState,
    wake: Wake,
    cx: &mut StepCx<'_, H>,
) -> (TransferState, Wake) {
    match next {
        mut s @ (TransferState::ProtoConnect(_)
        | TransferState::Do(_)
        | TransferState::Did(_)
        | TransferState::Exchanging(_)) => {
            let passed = progress::update(cx, false).and_then(|()| match s.pipeline_mut() {
                Some(p) => p.flush(cx),
                None => Ok(()),
            });
            match passed {
                Ok(()) => (s, wake),
                Err(e) => (s.fail(e), Wake::Again),
            }
        }
        TransferState::Done(d) if d.result.is_ok() => {
            match progress::update(cx, d.reached == Reached::Exchanged) {
                Ok(()) => (TransferState::Done(d), wake),
                // An abort ends the request early, closing its connection.
                Err(e) => (
                    TransferState::Done(Done {
                        result: Err(e),
                        ..d
                    }),
                    Wake::Again,
                ),
            }
        }
        s => (s, wake),
    }
}

/// A step of the connection's setup (`multistate_connecting`): not while
/// receiving is paused, and not past the connect deadline
/// (`multi_handle_timeout`).
fn connecting<H: Host>(
    run: &mut Run,
    c: Connecting,
    cx: &mut StepCx<'_, H>,
) -> (TransferState, Wake) {
    let now = cx.rest.now;
    if let TimeLeft::Expired(_) = run.deadlines.time_left(now, Phase::Connecting) {
        let ms = run.deadlines.since_leg_ms(now);
        let kind = ErrorKind::OperationTimedout;
        let kind = trace::fail(
            cx,
            kind,
            format_args!("Connection timed out after {ms} milliseconds"),
        );
        return (TransferState::Connecting(c).fail(kind), Wake::Again);
    }
    if StepCx::pause(cx).recv != RecvPause::Running {
        return (TransferState::Connecting(c), Wake::Idle);
    }
    let (pool, mut net) = cx.rest.pool_net(cx.me);
    match pool.connect(&c.lease, &mut net, now) {
        Ok(Connected::Connecting(Progress::Trying(to))) => {
            // A literal's name is known at once.
            cx.mark(Timer::NameLookup);
            match to {
                SocketAddr::V4(_) => trace::info(cx, format_args!("  Trying {to}...")),
                // No address carries a zone yet, which C would show as
                // `scope_id=N` after the port.
                SocketAddr::V6(v6) => {
                    trace::info(cx, format_args!("  Trying [{}]:{}...", v6.ip(), v6.port()));
                }
            }
            (TransferState::Connecting(c), Wake::Again)
        }
        Ok(Connected::Connecting(Progress::Waiting)) => (TransferState::Connecting(c), Wake::Idle),
        Ok(Connected::Established { remote, local, at }) => {
            cx.report_mut().timings_mut().mark(Timer::Connect, at);
            let host = c.origin.shown();
            let (lip, lport) = local.map_or((None, 0), |l| (Some(l.ip()), l.port()));
            let lip = Ip(lip);
            trace::info(
                cx,
                format_args!(
                    "Established connection to {host} ({} port {}) from {lip} port {lport} ",
                    remote.ip(),
                    remote.port()
                ),
            );
            (c.attached(), Wake::Again)
        }
        // A reused connection is up: nothing to trace or time
        // (`Curl_conn_connect` returns before `conn_connect_trace`).
        Ok(Connected::AlreadyUp) => (c.attached(), Wake::Again),
        Err(e) => {
            let kind = connect_failed(cx, &c.origin, e);
            (TransferState::Connecting(c).fail(kind), Wake::Again)
        }
    }
}

/// Why the setup failed, as C traces it (`cf_tcp_connect`,
/// `is_connected`).
fn connect_failed<H: Host>(cx: &mut StepCx<'_, H>, origin: &Origin, e: ConnectError) -> ErrorKind {
    let host = origin.name();
    let port = origin.port;
    match e {
        ConnectError::Unresolved => {
            trace::info(cx, format_args!("Could not resolve: {host}:{port}"));
            let kind = ErrorKind::CouldntResolveHost;
            return trace::fail(cx, kind, format_args!("Could not resolve host: {host}"));
        }
        ConnectError::Immediate { remote, error } => {
            let why = OsError(&error);
            trace::info(
                cx,
                format_args!("Immediate connect fail for {}: {why}", remote.ip()),
            );
        }
        ConnectError::Attempt {
            remote,
            local,
            error,
        } => {
            let (lip, lport) = local.map_or((None, 0), |l| (Some(l.ip()), l.port()));
            let lip = Ip(lip);
            let why = OsError(&error);
            trace::info(
                cx,
                format_args!(
                    "connect to {} port {} from {lip} port {lport} failed: {why}",
                    remote.ip(),
                    remote.port()
                ),
            );
        }
    }
    let ms = cx.easy().report().timings().since_single_ms(cx.rest.now);
    trace::fail(
        cx,
        ErrorKind::CouldntConnect,
        format_args!(
            "Failed to connect to {host}:{port} after {ms} ms: Could not connect to server"
        ),
    )
}

/// Bytes shown as text, as C's `%s` shows them.
struct Bytes<'a>(&'a [u8]);

impl std::fmt::Display for Bytes<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for chunk in self.0.utf8_chunks() {
            f.write_str(chunk.valid())?;
            for b in chunk.invalid() {
                f.write_char(char::from(*b))?;
            }
        }
        Ok(())
    }
}

/// A local address, or C's empty one when none is known.
struct Ip(Option<IpAddr>);

impl std::fmt::Display for Ip {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.0 {
            Some(ip) => ip.fmt(f),
            None => Ok(()),
        }
    }
}

/// An operating system error as `strerror` words it, without std's
/// "(os error N)".
pub(crate) struct OsError<'a>(pub(crate) &'a std::io::Error);

impl std::fmt::Display for OsError<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let (text, _) = Text::<256>::clipped(format_args!("{}", self.0));
        let mut bytes = text.bytes();
        if let Some(code) = self.0.raw_os_error() {
            let (suffix, _) = Text::<32>::clipped(format_args!(" (os error {code})"));
            bytes = bytes.strip_suffix(suffix.bytes()).unwrap_or(bytes);
        }
        Bytes(bytes).fmt(f)
    }
}

/// The request ran out of time, with what it received of how much.
fn timed_out<H: Host>(cx: &mut StepCx<'_, H>) -> ErrorKind {
    let report = cx.easy().report();
    let ms = report.timings().since_single_ms(cx.rest.now);
    let sizes = report.sizes();
    let got = sizes.download();
    let kind = ErrorKind::OperationTimedout;
    match sizes.download_expected() {
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

/// The report of a transfer completing, from before the request was
/// about to be sent or not (`mstate_enter_completed`, `Curl_pgrsCompleted`).
fn enter_completed(report: &mut TransferReport, now: Instant, before_did: bool) {
    let t = report.timings_mut();
    if before_did {
        // The times a jump to the end skipped.
        t.mark(Timer::PreTransfer, now);
        t.mark(Timer::PostTransfer, now);
        t.mark(Timer::StartTransfer, now);
    }
    t.completed(now);
}

/// A transfer that never ran, ended by its multi: its report starts and
/// completes at once.
pub(crate) fn complete_unstarted(easy: &mut Easy, now: Instant) {
    let report = easy.report_mut();
    report.restart(now);
    enter_completed(report, now, true);
}

/// `multi_done` treats these failures as premature whatever the caller
/// said.
fn is_premature(result: Result<(), ErrorKind>) -> bool {
    matches!(
        result,
        Err(ErrorKind::AbortedByCallback | ErrorKind::ReadError | ErrorKind::WriteError)
    )
}

/// C's pretransfer, SETUP and CONNECT, which always run in one pass: the
/// URL, the leg's timers, the protocol and a connection, then the protocol
/// connects over it.
fn setup<H: Host>(run: &mut Run, cx: &mut StepCx<'_, H>) -> TransferState {
    #[cfg(feature = "debug-hooks")]
    if std::mem::take(&mut run.warn) {
        trace::info(cx, format_args!("!!! WARNING !!!"));
        trace::info(
            cx,
            format_args!("This is a debug build of libcurl, do not use in production."),
        );
    }
    if cx.easy().options().url().is_none() {
        let kind = trace::fail(cx, ErrorKind::UrlMalformat, format_args!("No URL set"));
        return TransferState::Init.fail(kind);
    }
    cx.mark(Timer::StartOp);
    run.deadlines.start_leg(cx.rest.now);
    cx.mark(Timer::StartSingle);
    cx.mark(Timer::PostQueue);
    let options = cx.easy().options();
    let url = match parse_url(options) {
        Ok(url) => url,
        Err(UrlRefused::Rejected(e)) => {
            let kind = trace::fail(cx, url_error(e), format_args!("URL rejected: {e}"));
            return TransferState::Init.fail(kind);
        }
        Err(UrlRefused::Failed(kind)) => return TransferState::Init.fail(kind),
    };
    let scheme = match url.get(Part::Scheme, GetOptions::NONE) {
        Ok(s) => s,
        Err(e) => return TransferState::Init.fail(url_error(e)),
    };
    // Known before the protocol opens anything, as C records it.
    cx.report_mut().set_protocol(Protocol::of_scheme(&scheme));
    let proto = match ProtoState::start(&scheme, &url, cx) {
        Ok(Some(proto)) => proto,
        Ok(None) => {
            // A scheme libcurl knows is one this build leaves out.
            let why: &[u8] = if url::is_known_scheme(&scheme) {
                b"\" is disabled"
            } else {
                b"\" not supported"
            };
            let kind = ErrorKind::UnsupportedProtocol;
            let kind = trace::fail_with(cx, kind, &[b"Protocol \"", &scheme, why]);
            return TransferState::Init.fail(kind);
        }
        Err(e) => return TransferState::Init.fail(e),
    };
    let target = match proto.network(&url) {
        Ok(target) => target,
        Err(e) => return TransferState::Init.fail(e),
    };
    let Some((scheme, host, port)) = target else {
        let lease = match acquire(cx, Route::Local) {
            Ok(Acquired::New(lease)) => lease,
            Ok(Acquired::Reused(_)) => unreachable!("a connection without a network is never kept"),
            Err(OutOfMemory) => return TransferState::Init.fail(ErrorKind::OutOfMemory),
        };
        // A connection without a network has its name at once.
        cx.mark(Timer::NameLookup);
        return TransferState::ProtoConnect(Attached {
            lease,
            proto,
            origin: None,
        });
    };
    let Ok(dest) = Destination::new(&host, port) else {
        return TransferState::Init.fail(ErrorKind::OutOfMemory);
    };
    let origin = Origin { host, port };
    let lease = match acquire(cx, Route::Tcp(scheme, dest)) {
        Ok(Acquired::New(lease)) => lease,
        Ok(Acquired::Reused(lease)) => {
            let host = origin.name();
            let name = scheme.name;
            trace::info(
                cx,
                format_args!("Reusing existing {name}: connection with host {host}"),
            );
            lease
        }
        Err(OutOfMemory) => return TransferState::Init.fail(ErrorKind::OutOfMemory),
    };
    TransferState::Connecting(Connecting {
        lease,
        proto,
        origin,
    })
}

/// A connection for the transfer, and the trace of what the search for
/// one did.
fn acquire<H: Host>(cx: &mut StepCx<'_, H>, route: Route) -> Result<Acquired, OutOfMemory> {
    let limits = cx.easy().options().limits.reuse;
    let rules = ReuseRules {
        max_idle: limits.max_idle.map(TimeLimit::duration),
        max_age: limits.max_age.map(TimeLimit::duration),
    };
    let mut notes = Vec::new();
    let now = cx.rest.now;
    let (pool, mut net) = cx.rest.pool_net(cx.me);
    let acquired = pool.acquire(route, rules, &mut net, now, &mut notes)?;
    for note in notes {
        match note {
            PoolNote::IdleTooLong { idle_ms, max_ms } => trace::info(
                cx,
                format_args!(
                    "Too old connection ({idle_ms} ms idle, max idle is {max_ms} ms), disconnect it"
                ),
            ),
            PoolNote::Dead(n) => {
                let n = n.get();
                trace::info(
                    cx,
                    format_args!("Connection {n} seems to be dead, terminating"),
                );
            }
            PoolNote::Closed(n) => trace::info(cx, format_args!("shutting down connection {n}")),
        }
    }
    Ok(acquired)
}

/// Why a transfer's URL was not taken.
#[derive(Debug, PartialEq, Eq)]
enum UrlRefused {
    /// The parser's reason, which the transfer gives.
    Rejected(UrlErrorKind),
    /// Something else, without a reason given.
    Failed(ErrorKind),
}

/// The transfer's URL, parsed, given the default scheme where it has none
/// (`parseurlandfillconn`).
fn parse_url(options: &Options) -> Result<Url, UrlRefused> {
    let url = options.url().expect("checked by the caller");
    let parse = ParseOptions {
        guess_scheme: true,
        non_support_scheme: true,
        disallow_user: options.url_rules.disallow_user,
        path_as_is: options.url_rules.path_as_is,
        ..ParseOptions::NONE
    };
    let Some(default) = options.default_protocol() else {
        return Url::parse(url, parse).map_err(UrlRefused::Rejected);
    };
    // A path is no URL without `file:`, so for `file` the scheme is looked
    // for before parsing.
    if !default.eq_ignore_ascii_case(b"file") || url::has_scheme(url) {
        let parsed = Url::parse(url, parse).map_err(UrlRefused::Rejected)?;
        let no_guess = GetOptions {
            no_guess_scheme: true,
            ..GetOptions::NONE
        };
        match parsed.get(Part::Scheme, no_guess) {
            Ok(_) => return Ok(parsed),
            Err(UrlErrorKind::NoScheme) => {}
            Err(e) => return Err(UrlRefused::Failed(url_error(e))),
        }
    }
    let mut with_scheme = Vec::new();
    for part in [default, b"://", url] {
        with_scheme
            .try_extend_from_slice(part)
            .map_err(|_| UrlRefused::Failed(ErrorKind::OutOfMemory))?;
    }
    Url::parse(&with_scheme, parse).map_err(UrlRefused::Rejected)
}

/// A URL's error as a transfer's (`Curl_uc_to_curlcode`).
pub(crate) fn url_error(e: UrlErrorKind) -> ErrorKind {
    match e {
        UrlErrorKind::UnsupportedScheme => ErrorKind::UnsupportedProtocol,
        UrlErrorKind::OutOfMemory => ErrorKind::OutOfMemory,
        UrlErrorKind::UserNotAllowed => ErrorKind::LoginDenied,
        _ => ErrorKind::UrlMalformat,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `Curl_uc_to_curlcode`.
    #[test]
    fn url_errors_map_as_c_maps_them() {
        assert_eq!(
            url_error(UrlErrorKind::UnsupportedScheme),
            ErrorKind::UnsupportedProtocol
        );
        assert_eq!(url_error(UrlErrorKind::OutOfMemory), ErrorKind::OutOfMemory);
        assert_eq!(
            url_error(UrlErrorKind::UserNotAllowed),
            ErrorKind::LoginDenied
        );
        assert_eq!(
            url_error(UrlErrorKind::BadHostname),
            ErrorKind::UrlMalformat
        );
    }

    /// The URL a transfer with `default` as its default protocol fetches.
    fn with_default(default: Option<&str>, url: &str) -> Result<Vec<u8>, ErrorKind> {
        let mut options = Options::default();
        options.set_url(Some(url.as_bytes())).unwrap();
        options
            .set_default_protocol(default.map(str::as_bytes))
            .unwrap();
        let url = parse_url(&options).map_err(|e| match e {
            UrlRefused::Rejected(e) => url_error(e),
            UrlRefused::Failed(kind) => kind,
        })?;
        Ok(url.get(Part::Url, GetOptions::NONE).unwrap())
    }

    /// A URL without a scheme gets the default one; `file`, under which a
    /// path is no URL, is given before parsing (`parseurlandfillconn`).
    #[test]
    fn a_url_without_a_scheme_takes_the_default() {
        let url = |d, u| with_default(d, u).map(|u| String::from_utf8(u).unwrap());
        assert_eq!(url(None, "example.com/x").unwrap(), "http://example.com/x");
        assert_eq!(
            url(Some("ftp"), "example.com/x").unwrap(),
            "ftp://example.com/x"
        );
        assert_eq!(url(Some("ftp"), "http://h/x").unwrap(), "http://h/x");
        assert_eq!(url(Some("file"), "/dir/f").unwrap(), "file:///dir/f");
        assert_eq!(url(Some("FILE"), "/dir/f").unwrap(), "file:///dir/f");
        assert_eq!(url(Some("file"), "http://h/x").unwrap(), "http://h/x");
        // Test 4040: the first path segment becomes a host `file:` refuses.
        assert_eq!(
            url(Some("file"), "remote.example/etc/passwd"),
            Err(ErrorKind::UrlMalformat)
        );
        // Without `file`, the scheme is looked for once the URL is parsed:
        // one it cannot parse fails as it is.
        assert_eq!(url(Some("ftp"), "/dir/f"), Err(ErrorKind::UrlMalformat));
        // An unknown scheme is refused by the protocol lookup after.
        assert_eq!(
            url(Some("nosuch"), "example.com/x").unwrap(),
            "nosuch://example.com/x"
        );
    }
}
