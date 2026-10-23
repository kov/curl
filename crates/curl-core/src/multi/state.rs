//! A transfer's states and the steps between them (`multi_runsingle`).
//!
//! The variants hold what is valid in them: a connection lease exists from
//! the moment a transfer has a connection until `Done` gives it back, and
//! only `Done` gives it back.

use std::fmt::Write as _;
use std::net::{IpAddr, SocketAddr};
use std::num::NonZeroU32;

use curl_alloc::{OutOfMemory, TryArc, TryVec, try_box};

use crate::conn::io::{Events, ResolveFailure};
use crate::conn::pool;
use crate::conn::proxy::{self, Refused};
use crate::conn::{
    Acquired, Answer, BadEntry, BadVia, ConnLease, ConnectError, Connected, Failure, Finish, Found,
    Full, Limit, ListEntry, Peer, PoolNote, PreProxy, Progress, ProxyCreds, ProxyRoute, Released,
    ReuseRules, Route, Setup, Tcp, Unresolved, WaitReason, parse_entry,
};
use crate::deliver::{Directions, Pause, PauseRequest, Pipeline, RecvPause};
use crate::easy::Easy;
use crate::error::{ErrorKind, UrlErrorKind};
use crate::options::{Follow, Limits, Method, Options, ProxyType, ResolveList};
use crate::progress::rate::{RateLimits, Verdict, Way};
use crate::progress::{self, Speedometer};
use crate::proto::http::Challenged;
use crate::share::Kind;

mod haproxy;
mod socks;
mod tunnel;
use crate::proto::http1::follow;
use crate::proto::{Inherited, ProtoState, ProtoStep};
use crate::report::{Ends, Starts, Timer, TransferReport};
use crate::time::{Instant, TimeLimit};
use crate::trace;
use crate::url::{self, GetOptions, ParseOptions, Part, SetOptions, Url};
use crate::version::Protocol;

use super::cx::{EngineRest, TransferCalls};
use super::sched::RowSet;
use super::sockets::Pollset;
use super::timers::{Deadlines, Phase, TimeLeft, TimerKind, wait_ms};
use super::{Host, Slots, TransferId};

/// The longest host name a URL may name (`MAX_URL_LEN`).
const MAX_HOST: usize = 0xffff;

/// A transfer from `add` to `remove`.
#[derive(Debug)]
pub(crate) struct Run {
    pub(crate) state: TransferState,
    pub(crate) deadlines: Deadlines,
    /// The URL the request under way asked for, read back whole,
    /// credentials and all, without the application's port (C's
    /// `state.url`): a retry asks for it again.
    url: Vec<u8>,
    /// Requests made again on a fresh connection, their reused one having
    /// died (`state.retrycount`).
    retries: u8,
    /// What the next request takes from the ones before it.
    inherited: Inherited,
    /// The first transfer added to its multi says that the library is a
    /// debug build (`multi_warn_debug`).
    #[cfg(feature = "debug-hooks")]
    pub(crate) warn: bool,
}

impl Run {
    pub(crate) fn new() -> Run {
        Run {
            state: TransferState::Init,
            deadlines: Deadlines::new(None, None),
            url: Vec::new(),
            retries: 0,
            inherited: Inherited::new(Method::Get),
            #[cfg(feature = "debug-hooks")]
            warn: false,
        }
    }
}

/// The most times a request is made again on a fresh connection
/// (`CONN_MAX_RETRIES`).
const MAX_RETRIES: u8 = 5;

/// What follows a request.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum AfterRequest {
    /// The transfer is over.
    Complete,
    /// The same URL is asked for again on a fresh connection, the reused
    /// one having died (C's `FOLLOW_RETRY`).
    Retry,
    /// The response's `Location:`, as the server gave it, is followed
    /// (C's `FOLLOW_REDIR`); `code` is the response's.
    Follow { location: Vec<u8>, code: u16 },
}

#[derive(Debug)]
pub(crate) enum TransferState {
    /// Added, not yet run.
    Init,
    /// Waiting for room for a connection under the multi's limits (C's
    /// PENDING): not run until a connection is given back or its time
    /// is up.
    Pending(Plan),
    /// Let to look for a connection again (C's CONNECT, from PENDING).
    Setup(Plan),
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
    /// Exchanging, but over a speed limit: nothing moves, and nothing is
    /// waited for on the sockets, until the limit's timer says
    /// (RATELIMITING).
    RateLimiting(Attached),
    /// The request is over; the connection goes back at the next step.
    Done(Done),
    /// Over; its message is read or not. Terminal until removed.
    Completed(Completed),
}

/// What a request needs to set up its connection, kept while it waits for
/// one.
#[derive(Debug)]
pub(crate) struct Plan {
    proto: ProtoState,
    /// What the connection must be, decided once for the leg. Its origin
    /// is the proxy, for one the request goes to whole.
    route: Tcp,
}

/// A request whose connection is being set up.
#[derive(Debug)]
pub(crate) struct Connecting {
    lease: ConnLease,
    proto: ProtoState,
    /// The plan's route: the host and port the request is for, the peer
    /// connected to in their place and the proxy on the way, as the
    /// failure names them.
    route: Tcp,
    /// The handshake made over the connection to the proxy, once
    /// connected.
    handshake: Option<Box<Handshake>>,
}

/// A handshake with a proxy, over the connection to it.
#[derive(Debug)]
enum Handshake {
    Socks(socks::Socks),
    /// An HTTP proxy's tunnel, with `CONNECT`.
    Connect(tunnel::Tunnel),
    /// The PROXY protocol's line, once the connection is up.
    Haproxy(haproxy::Preface),
}

impl Handshake {
    /// What it waits for on the connection's socket.
    fn interest(&self) -> Events {
        match self {
            Handshake::Socks(s) => s.interest(),
            Handshake::Connect(t) => t.interest(),
            Handshake::Haproxy(p) => p.interest(),
        }
    }
}

/// Who the request is for (C's `conn->origin`), shared with the
/// connection's route.
type Origin = TryArc<Peer>;

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
    next: AfterRequest,
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
        self.lease().is_some()
    }

    /// The lease the transfer holds, if it holds one.
    pub(crate) fn lease(&self) -> Option<&ConnLease> {
        match self {
            TransferState::Connecting(c) => Some(&c.lease),
            TransferState::Done(d) => Some(&d.lease),
            _ => self.attached().map(|a| &a.lease),
        }
    }

    fn attached(&self) -> Option<&Attached> {
        match self {
            TransferState::ProtoConnect(x)
            | TransferState::Do(x)
            | TransferState::Did(x)
            | TransferState::Exchanging(x)
            | TransferState::RateLimiting(x) => Some(x),
            _ => None,
        }
    }

    fn attached_mut(&mut self) -> Option<&mut Attached> {
        match self {
            TransferState::ProtoConnect(x)
            | TransferState::Do(x)
            | TransferState::Did(x)
            | TransferState::Exchanging(x)
            | TransferState::RateLimiting(x) => Some(x),
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

    /// The ways the transfer's request moves bytes, which its pause is
    /// judged against: none until the request is made, nor once it is
    /// over (`xfer_setup`, `Curl_req_stop_send_recv`).
    pub(crate) fn directions(&self, options: &Options) -> Directions {
        match self {
            TransferState::Did(x)
            | TransferState::Exchanging(x)
            | TransferState::RateLimiting(x) => x.proto.directions(options),
            _ => Directions::default(),
        }
    }

    /// When the protocol wants to look again whatever its socket says.
    pub(crate) fn wake_at(&self) -> Option<Instant> {
        match self {
            TransferState::Did(x)
            | TransferState::Exchanging(x)
            | TransferState::RateLimiting(x) => x.proto.wake_at(),
            _ => None,
        }
    }

    /// End the transfer with `err`: through `Done` if it holds a
    /// connection, straight to `Completed` if not. A transfer already
    /// finishing keeps its result, as `multi_done` runs once.
    pub(crate) fn fail(self, err: ErrorKind) -> TransferState {
        match self {
            TransferState::Init | TransferState::Pending(_) | TransferState::Setup(_) => {
                TransferState::Completed(Completed {
                    outcome: Err(err),
                    message: Message::Unread,
                })
            }
            TransferState::Connecting(c) => TransferState::Done(Done {
                lease: c.lease,
                proto: None,
                result: Err(err),
                premature: true,
                reached: Reached::Unmade,
                origin: Some(c.route.origin),
                next: AfterRequest::Complete,
            }),
            TransferState::ProtoConnect(x) | TransferState::Do(x) => {
                TransferState::Done(x.done(Err(err), true, Reached::Unmade))
            }
            TransferState::Did(x)
            | TransferState::Exchanging(x)
            | TransferState::RateLimiting(x) => {
                TransferState::Done(x.done(Err(err), true, Reached::Made))
            }
            s @ (TransferState::Done(_) | TransferState::Completed(_)) => s,
        }
    }

    /// Take the transfer out of the multi before it completed: give back
    /// its connection, as a premature end (`curl_multi_remove_handle`).
    pub(crate) fn abandon<H: Host>(self, cx: &mut StepCx<'_, H>) {
        let (lease, origin) = match self {
            TransferState::Init
            | TransferState::Pending(_)
            | TransferState::Setup(_)
            | TransferState::Completed(_) => return,
            TransferState::Connecting(c) => (c.lease, Some(c.route.origin)),
            TransferState::ProtoConnect(x)
            | TransferState::Do(x)
            | TransferState::Did(x)
            | TransferState::Exchanging(x)
            | TransferState::RateLimiting(x) => (x.lease, x.origin),
            TransferState::Done(d) => (d.lease, d.origin),
        };
        release(cx, lease, true, origin.as_ref());
    }
}

/// Give the transfer's connection back, and trace its fate
/// (`Curl_cpool_return`, `cpool_conn_close`).
fn release<H: Host>(
    cx: &mut StepCx<'_, H>,
    lease: ConnLease,
    premature: bool,
    origin: Option<&Origin>,
) {
    let finish = Finish {
        premature,
        forbid_reuse: cx.easy().options().limits.reuse.forbid,
    };
    let now = cx.rest.now;
    let limit = Limit {
        max: cx.rest.tell.limits.max_connects,
        attached: cx.rest.tell.slots.len(),
    };
    if lease.answer().is_some() {
        // A setup given up lets its answer go (`CF_CTRL_DATA_DONE`).
        let kept = cx.rest.kept(cx.me, Kind::Names);
        cx.rest.net_names(cx.me, kept.as_ref()).1.release();
    }
    let home = lease.home().cloned();
    let released = cx.rest.pool_section(cx.me, home.as_ref(), |pool, net| {
        pool.release(lease, finish, limit, net, now)
    });
    if let Released::Idle {
        full: Some(full), ..
    }
    | Released::Evicted(full) = released
    {
        let Full { conns, max } = full;
        trace::info(
            cx,
            format_args!("Connection pool is full, closing the oldest of {conns}/{max}"),
        );
    }
    match released {
        // Gone as it came back: not the transfer's any more.
        Released::Evicted(_) => cx.report_mut().set_conn(None),
        Released::Idle { number: n, .. } => {
            let origin = origin.expect("a connection kept has a host");
            let (host, port) = (Bytes(origin.shown()), origin.port());
            trace::info(
                cx,
                format_args!("Connection {n} to host {host}:{port} left intact"),
            );
        }
        Released::Closed(n) => trace::info(cx, format_args!("shutting down connection {n}")),
        Released::Terminated(n) => trace::info(cx, format_args!("closing connection {n}")),
    }
    // Room, perhaps, for one waiting (`multi_done`).
    schedule_pending(&mut cx.rest);
}

impl TransferState {
    /// The sockets the transfer waits on, and for what
    /// (`Curl_multi_pollset`): a setup waits to write on each, unless
    /// receiving is paused (`mstate_connecting_pollset`); an exchange
    /// waits for what its protocol says (`Curl_http_perform_pollset`);
    /// one over its speed limit waits on nothing but its timer (C's
    /// RATELIMITING has no pollset). An exchange is never over a limit,
    /// so C's taking a limited direction out (`multi_adjust_pollset`)
    /// leaves only the pause's, which the protocol applies.
    pub(crate) fn pollset(&self, pause: Pause) -> Pollset<'_> {
        let mut set = Pollset::new();
        match self {
            TransferState::Connecting(c) if pause.recv == RecvPause::Running => {
                // A tunnel's handshake waits for what it sends or reads.
                let events = c.handshake.as_ref().map_or(Events::OUT, |h| h.interest());
                for s in c.lease.sockets() {
                    set.add(s, events);
                }
            }
            TransferState::Exchanging(x) => {
                let events = x.proto.interest(pause);
                for s in x.lease.sockets() {
                    set.add(s, events);
                }
            }
            _ => {}
        }
        set
    }
}

impl Connecting {
    /// The connection is up: on to the protocol's connect.
    fn attached(self) -> TransferState {
        let Connecting {
            lease,
            proto,
            route,
            handshake: _,
        } = self;
        TransferState::ProtoConnect(Attached {
            lease,
            proto,
            origin: Some(route.origin),
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
            next: AfterRequest::Complete,
        }
    }

    /// The request is over, to be made again on a fresh connection.
    fn retried(self, result: Result<(), ErrorKind>, reached: Reached) -> Done {
        Done {
            next: AfterRequest::Retry,
            ..self.done(result, false, reached)
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
            .tell
            .slots
            .get(self.me)
            .expect("the stepping transfer")
            .easy
    }
}

impl<H: Host> StepCx<'_, H> {
    pub(crate) fn report_mut(&mut self) -> &mut TransferReport {
        self.rest
            .tell
            .slots
            .get_mut(self.me)
            .expect("the stepping transfer")
            .easy
            .report_mut()
    }

    pub(crate) fn pause(&self) -> Pause {
        self.rest
            .tell
            .slots
            .get(self.me)
            .expect("the stepping transfer")
            .pause
    }

    pub(crate) fn pause_mut(&mut self) -> &mut Pause {
        &mut self
            .rest
            .tell
            .slots
            .get_mut(self.me)
            .expect("the stepping transfer")
            .pause
    }

    pub(crate) fn now(&self) -> Instant {
        self.rest.now
    }

    /// The transfer's time is up, as of the step's start
    /// (`Curl_timeleft_ms` below zero).
    pub(crate) fn time_up(&self) -> bool {
        let limits = self.easy().options().limits;
        let left = Deadlines::new(limits.total, limits.connect).time_left(
            starts(self),
            self.now(),
            Phase::Transferring,
        );
        matches!(left, TimeLeft::Expired(_))
    }

    /// The calendar time, read now (`time(NULL)`).
    pub(crate) fn unix_time(&self) -> i64 {
        self.rest.clock.unix_time()
    }

    pub(crate) fn easy_mut(&mut self) -> &mut Easy {
        &mut self
            .rest
            .tell
            .slots
            .get_mut(self.me)
            .expect("the stepping transfer")
            .easy
    }

    pub(crate) fn speedometer_mut(&mut self) -> &mut Speedometer {
        &mut self
            .rest
            .tell
            .slots
            .get_mut(self.me)
            .expect("the stepping transfer")
            .speedometer
    }

    /// The speedometer and the report it writes to.
    pub(crate) fn progress_parts(&mut self) -> (&mut Speedometer, &mut TransferReport) {
        let slot = self
            .rest
            .tell
            .slots
            .get_mut(self.me)
            .expect("the stepping transfer");
        (&mut slot.speedometer, slot.easy.report_mut())
    }

    /// The speed limits' buckets, with the limits and the pause they are
    /// read with.
    fn rate_parts(&mut self) -> (&mut RateLimits, &Limits, Pause, Instant) {
        let now = self.rest.now;
        let slot = self
            .rest
            .tell
            .slots
            .get_mut(self.me)
            .expect("the stepping transfer");
        (&mut slot.rate, &slot.easy.options().limits, slot.pause, now)
    }

    /// How many bytes `way` may move now, if it is limited
    /// (`Curl_rlimit_avail`); none while it is paused.
    pub(crate) fn rate_allowance(&mut self, way: Way) -> Option<i64> {
        let (rate, limits, pause, now) = self.rate_parts();
        rate.allowance(way, limits, pause, now)
    }

    /// `n` bytes moved `way`: the limit takes them (`Curl_rlimit_drain`).
    pub(crate) fn rate_drain(&mut self, way: Way, n: usize) {
        let (rate, limits, pause, now) = self.rate_parts();
        rate.drain(way, limits, pause, n, now);
    }

    /// The limit on `way` starts afresh, tuned for `total` bytes if known
    /// (`Curl_rlimit_start`).
    pub(crate) fn rate_start(&mut self, way: Way, total: Option<u64>) {
        let (rate, limits, _, now) = self.rate_parts();
        rate.start(way, limits, now, total);
    }

    /// Whether the limits make the transfer wait (`mspeed_check`).
    fn rate_verdict(&mut self) -> Verdict {
        let (rate, limits, pause, now) = self.rate_parts();
        rate.verdict(limits, pause, now)
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
        self.rest.tell.slots.get(id).map(|s| &*s.easy)
    }

    fn easy_mut(&mut self, id: TransferId) -> Option<&mut Easy> {
        self.rest.tell.slots.get_mut(id).map(|s| &mut *s.easy)
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

/// When the running transfer and its request started.
fn starts<H: Host>(cx: &StepCx<'_, H>) -> Starts {
    cx.easy()
        .report()
        .timings()
        .starts()
        .expect("a running transfer has started")
}

/// Run one step of `run`.
pub(crate) fn step<H: Host>(run: &mut Run, cx: &mut StepCx<'_, H>) -> Wake {
    let state = std::mem::replace(&mut run.state, TransferState::Init);
    let (next, wake) = match state {
        TransferState::Init => {
            let limits = cx.easy().options().limits;
            run.deadlines = Deadlines::new(limits.total, limits.connect);
            let now = cx.rest.now;
            cx.report_mut().restart(now);
            *cx.speedometer_mut() = Speedometer::default();
            let next = match pretransfer(run, cx) {
                Ok(url) => start_leg(run, cx, url),
                Err(kind) => TransferState::Init.fail(kind),
            };
            if next.is_completed() {
                enter_completed(cx.report_mut(), now, true);
            }
            (next, Wake::Again)
        }
        TransferState::Pending(plan) => pending(run, plan, cx),
        TransferState::Setup(mut plan) => {
            // The rest of the plan is kept, but C makes its connection
            // anew as a waiting transfer looks again, reading the IP
            // version then (`allocate_conn`, `url_match_conn`).
            plan.route.ip = cx.easy().options().ip_version;
            let now = cx.rest.now;
            let next = match run.deadlines.time_left(starts(cx), now, Phase::Connecting) {
                TimeLeft::Expired(_) => {
                    let kind = timed_out(cx);
                    // Its failure may make room for another
                    // (`multi_runsingle`).
                    schedule_pending(&mut cx.rest);
                    TransferState::Init.fail(kind)
                }
                TimeLeft::Remaining(_) | TimeLeft::Unlimited => setup(cx, plan),
            };
            if next.is_completed() {
                enter_completed(cx.report_mut(), now, true);
            }
            (next, Wake::Again)
        }
        TransferState::Connecting(c) => connecting(run, c, cx),
        // No protocol connects over its connection yet.
        TransferState::ProtoConnect(x) => (TransferState::Do(x), Wake::Again),
        TransferState::Do(mut x) => match x.proto.do_it(cx, &mut x.lease) {
            Ok(()) => {
                // About to send; sent already, with no body
                // (`mstate_enter_did`).
                cx.mark(Timer::PreTransfer);
                let send = x.proto.wants_send(cx.easy().options());
                if !send {
                    cx.mark(Timer::PostTransfer);
                }
                (TransferState::Did(x), Wake::Again)
            }
            // A reused connection that died may be the request's
            // trouble: it is made again on a fresh one (`multistate_do`).
            Err(ErrorKind::SendError) if x.lease.conn().reused() => {
                let next = match retry_request(run, &mut x, cx) {
                    Ok(true) => x.retried(Err(ErrorKind::SendError), Reached::Unmade),
                    Ok(false) => x.done(Err(ErrorKind::SendError), false, Reached::Unmade),
                    Err(e) => x.done(Err(e), false, Reached::Unmade),
                };
                (TransferState::Done(next), Wake::Again)
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
        TransferState::Exchanging(x) if over_limit(run, cx) => {
            // Over a speed limit: nothing moves until it says
            // (`multistate_performing`'s first `mspeed_check`), but the
            // time limit holds (`multi_handle_timeout`).
            if expired(run, cx) {
                let kind = timed_out(cx);
                (TransferState::Exchanging(x).fail(kind), Wake::Again)
            } else {
                (TransferState::RateLimiting(x), Wake::Idle)
            }
        }
        TransferState::RateLimiting(x) => {
            if expired(run, cx) {
                let kind = timed_out(cx);
                (TransferState::RateLimiting(x).fail(kind), Wake::Again)
            } else {
                // The progress and the low-speed check, then the limits
                // again (`multistate_ratelimiting`).
                match progress::check(cx, false) {
                    Err(e) => (TransferState::RateLimiting(x).fail(e), Wake::Again),
                    Ok(look_again) => {
                        if let Some(wait) = look_again {
                            run.deadlines.arm_in(TimerKind::SpeedCheck, cx.now(), wait);
                        }
                        if over_limit(run, cx) {
                            (TransferState::RateLimiting(x), Wake::Idle)
                        } else {
                            (TransferState::Exchanging(x), Wake::Again)
                        }
                    }
                }
            }
        }
        TransferState::Exchanging(mut x) => {
            let stepped = x.proto.step(cx, &mut x.lease);
            let expired = expired(run, cx);
            match stepped {
                // Received nothing, perhaps over a reused connection that
                // closed as it was reused (`multistate_performing`).
                Err(ErrorKind::RecvError) => match retry_request(run, &mut x, cx) {
                    Ok(true) => (
                        TransferState::Done(x.retried(Ok(()), Reached::Made)),
                        Wake::Again,
                    ),
                    // The receive's failure stands over the retry's.
                    Ok(false) | Err(_) => (
                        TransferState::Exchanging(x).fail(ErrorKind::RecvError),
                        Wake::Again,
                    ),
                },
                Err(e) => (TransferState::Exchanging(x).fail(e), Wake::Again),
                // Out of time at the end of the pass (transfer.c:382).
                Ok(ProtoStep::Blocked | ProtoStep::AtReadLimit) if expired => {
                    let kind = timed_out(cx);
                    (TransferState::Exchanging(x).fail(kind), Wake::Again)
                }
                Ok(stepped) => {
                    // The end of a receive pass (`Curl_sendrecv`). A request
                    // is not over while output waits for the application to
                    // unpause (`multi.c`: `req.done` and the writers not
                    // paused).
                    let ended = stepped == ProtoStep::Done;
                    let done = ended && !x.proto.holds_output();
                    match progress::check(cx, done) {
                        Err(e) => (TransferState::Exchanging(x).fail(e), Wake::Again),
                        Ok(look_again) => {
                            if let Some(wait) = look_again {
                                run.deadlines.arm_in(TimerKind::SpeedCheck, cx.now(), wait);
                            }
                            let retry = if ended {
                                retry_request(run, &mut x, cx)
                            } else {
                                Ok(false)
                            };
                            if let Err(e) = retry {
                                (TransferState::Exchanging(x).fail(e), Wake::Again)
                            } else if retry == Ok(true) {
                                (
                                    TransferState::Done(x.retried(Ok(()), Reached::Made)),
                                    Wake::Again,
                                )
                            } else if done {
                                match after_exchange(run, &mut x, cx) {
                                    Ok(next) => (
                                        TransferState::Done(Done {
                                            next,
                                            ..x.done(Ok(()), false, Reached::Exchanged)
                                        }),
                                        Wake::Again,
                                    ),
                                    Err(e) => (TransferState::Exchanging(x).fail(e), Wake::Again),
                                }
                            } else {
                                if stepped == ProtoStep::AtReadLimit {
                                    // Run again in the next pass, without
                                    // waiting for the socket
                                    // (`Curl_multi_mark_dirty`).
                                    cx.rest.dirty.insert(cx.me.index());
                                }
                                // Over a speed limit now, it waits, its
                                // run in the next pass called off.
                                if over_limit(run, cx) {
                                    (TransferState::RateLimiting(x), Wake::Idle)
                                } else {
                                    (TransferState::Exchanging(x), Wake::Idle)
                                }
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
                d.result = proto.done(cx, &mut d.lease, d.result, premature, &d.next);
            }
            // A last progress pass, unless a callback aborted already.
            if d.result != Err(ErrorKind::AbortedByCallback)
                && let Err(e) = progress::finish(cx, d.reached == Reached::Exchanged)
                && d.result.is_ok()
            {
                d.result = Err(e);
                premature |= is_premature(d.result);
            }
            crate::deliver::Pipeline::done(cx);
            let max_age = cx.easy().options().limits.reuse.dns_max_age;
            let now = cx.rest.now;
            let kept = cx.rest.kept(cx.me, Kind::Names);
            let (_, mut names) = cx.rest.net_names(cx.me, kept.as_ref());
            names.section(|dns| dns.prune(now, max_age));
            release(cx, d.lease, premature, d.origin.as_ref());
            // Held output went with the request; a pause the application
            // asked for stays.
            let pause = cx.pause_mut();
            if pause.recv == RecvPause::Held {
                pause.recv = RecvPause::Running;
                // Unpaused, the limit starts over (`Curl_req_reset`).
                cx.rate_start(Way::Recv, None);
            }
            let now = cx.rest.now;
            if d.proto.as_ref().is_some_and(ProtoState::saw_http10) {
                run.inherited.http10 = true;
            }
            let leg = match (&d.next, d.result, d.proto.as_mut()) {
                // A send failure is what a retry from DO set out to mend.
                (AfterRequest::Retry, Ok(()) | Err(ErrorKind::SendError), Some(proto)) => {
                    Some(retry_leg(run, cx, proto))
                }
                (AfterRequest::Follow { location, code }, Ok(()), Some(proto)) => {
                    Some(follow_leg(run, cx, proto, location, *code))
                }
                _ => None,
            };
            if let Some(next) = leg {
                if next.is_completed() {
                    enter_completed(cx.report_mut(), now, true);
                }
                (next, Wake::Again)
            } else {
                enter_completed(cx.report_mut(), now, d.reached == Reached::Unmade);
                let completed = TransferState::Completed(Completed {
                    outcome: d.result,
                    message: Message::Unread,
                });
                (completed, Wake::Again)
            }
        }
        s @ TransferState::Completed(_) => (s, Wake::Idle),
    };
    let (next, wake) = progress_after_step(next, wake, cx);
    run.state = next;
    wake
}

/// Whether the transfer's time is up, as of the pass's start.
fn expired<H: Host>(run: &Run, cx: &StepCx<'_, H>) -> bool {
    matches!(
        run.deadlines
            .time_left(starts(cx), cx.rest.now, Phase::Transferring),
        TimeLeft::Expired(_)
    )
}

/// Whether the speed limits make the transfer wait now, its timer armed
/// for the wait and its run in the next pass called off; if not, the
/// timer is armed for when a limit next earns tokens, as the transfer
/// may need them to go on (`mspeed_check`, `EXPIRE_TOOFAST`).
fn over_limit<H: Host>(run: &mut Run, cx: &mut StepCx<'_, H>) -> bool {
    match cx.rate_verdict() {
        Verdict::Wait(wait) => {
            run.deadlines.arm_in(TimerKind::TooFast, cx.now(), wait);
            cx.rest.dirty.remove(cx.me.index());
            true
        }
        Verdict::Go(next) => {
            if let Some(next) = next {
                run.deadlines.arm_in(TimerKind::TooFast, cx.now(), next);
            }
            false
        }
    }
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
        | TransferState::Exchanging(_)
        | TransferState::RateLimiting(_)) => {
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

/// A transfer waiting for a connection runs only to find its time up
/// (`multi_handle_timeout` from the timer sweep, "PENDING handle
/// timeout"), and then fails as it looks for one again.
fn pending<H: Host>(run: &mut Run, plan: Plan, cx: &mut StepCx<'_, H>) -> (TransferState, Wake) {
    let now = cx.rest.now;
    match run.deadlines.time_left(starts(cx), now, Phase::Connecting) {
        TimeLeft::Expired(_) => {
            timed_out(cx);
            trace::info(cx, format_args!("PENDING handle timeout"));
            (TransferState::Setup(plan), Wake::Again)
        }
        TimeLeft::Remaining(_) | TimeLeft::Unlimited => (TransferState::Pending(plan), Wake::Idle),
    }
}

/// A step of the connection's setup (`multistate_connecting`): not while
/// receiving is paused, and not past the connect deadline
/// (`multi_handle_timeout`).
fn connecting<H: Host>(
    run: &mut Run,
    mut c: Connecting,
    cx: &mut StepCx<'_, H>,
) -> (TransferState, Wake) {
    let now = cx.rest.now;
    if let TimeLeft::Expired(_) = run.deadlines.time_left(starts(cx), now, Phase::Connecting) {
        let ms = cx.easy().report().timings().since_single_ms(now);
        let kind = ErrorKind::OperationTimedout;
        let kind = match c.handshake.as_deref() {
            Some(Handshake::Connect(_)) => trace::fail(
                cx,
                kind,
                format_args!("Proxy CONNECT aborted due to timeout"),
            ),
            Some(Handshake::Socks(_) | Handshake::Haproxy(_)) | None => trace::fail(
                cx,
                kind,
                format_args!("Connection timed out after {ms} milliseconds"),
            ),
        };
        return (TransferState::Connecting(c).fail(kind), Wake::Again);
    }
    if StepCx::pause(cx).recv != RecvPause::Running {
        return (TransferState::Connecting(c), Wake::Idle);
    }
    match c.handshake.as_deref() {
        Some(Handshake::Socks(_)) => return socks::step(c, cx),
        Some(Handshake::Connect(_)) => return tunnel::step(c, cx),
        Some(Handshake::Haproxy(_)) => return haproxy::step(c, cx),
        None => {}
    }
    let delay = cx.easy().options().limits.eyeballs.0;
    let wildcard = cx.easy().wildcard_resolve;
    let scope = cx.easy().options().address_scope;
    let max_age = cx.easy().options().limits.reuse.dns_max_age;
    let kept = cx.rest.kept(cx.me, Kind::Names);
    let answered = c.lease.answer().is_some();
    let (mut net, dns) = cx.rest.net_names(cx.me, kept.as_ref());
    let setup = Setup {
        dns,
        wildcard,
        max_age,
        delay,
        scope,
    };
    let connected = c.lease.connect(&mut net, now, setup);
    if answered && c.lease.answer().is_none() {
        // Connected, or failed: the answer is let go.
        cx.rest.net_names(cx.me, kept.as_ref()).1.release();
    }
    if !matches!(connected, Ok(Connected::Connecting(_))) {
        run.deadlines.clear(TimerKind::Eyeballs);
    }
    match connected {
        Ok(Connected::Connecting(Progress::Resolved(found))) => {
            match found {
                Found::Cached => {
                    // The name looked up: the proxy's, or what a
                    // connect-to names in the origin's place.
                    let name = Bytes(c.route.destination().name());
                    trace::info(cx, format_args!("Hostname {name} was found in DNS cache"));
                }
                Found::Stale => {
                    trace::info(cx, format_args!("Hostname in DNS cache was stale, zapped"))
                }
                Found::Resolved => {}
            }
            cx.mark(Timer::NameLookup);
            report_answer(cx, &c);
            (TransferState::Connecting(c), Wake::Again)
        }
        Ok(Connected::Connecting(Progress::Failed(failure))) => {
            trace_failure(cx, failure);
            (TransferState::Connecting(c), Wake::Again)
        }
        Ok(Connected::Connecting(Progress::Trying {
            remote,
            scope_found,
        })) => {
            trace_trying(cx, remote, scope_found);
            (TransferState::Connecting(c), Wake::Again)
        }
        Ok(Connected::Connecting(Progress::Dialed)) => dialed(c, cx),
        Ok(Connected::Connecting(Progress::Waiting { until })) => {
            match until {
                Some(at) => run
                    .deadlines
                    .arm_in(TimerKind::Eyeballs, now, wait_ms(now, at)),
                None => run.deadlines.clear(TimerKind::Eyeballs),
            }
            (TransferState::Connecting(c), Wake::Idle)
        }
        Ok(Connected::Established { remote, local, at }) => established(c, cx, remote, local, at),
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
            (TransferState::Connecting(c).fail(kind), Wake::Again)
        }
    }
}

/// Connected to the proxy: its handshake starts, SOCKS's or an HTTP
/// proxy's tunnel's. Each connection to the proxy counts as it is made.
fn dialed<H: Host>(c: Connecting, cx: &mut StepCx<'_, H>) -> (TransferState, Wake) {
    cx.report_mut().count_connect();
    match c.route.socks().map(|leg| leg.version) {
        Some(version) => socks::dialed(c, cx, version),
        None => tunnel::dialed(c, cx),
    }
}

/// A new connection is up, from `local` to `remote`, connected at `at`:
/// counted unless through a proxy's handshake, whose connections were
/// counted as each was made, then its PROXY line sent if the transfer
/// asks for one.
fn established<H: Host>(
    mut c: Connecting,
    cx: &mut StepCx<'_, H>,
    remote: SocketAddr,
    local: Option<SocketAddr>,
    at: Instant,
) -> (TransferState, Wake) {
    if c.handshake.is_none() {
        cx.report_mut().count_connect();
    }
    match haproxy::wanted(cx, remote, local, at) {
        Ok(None) => up(c, cx, remote, local, at),
        Ok(Some(preface)) => match try_box(Handshake::Haproxy(preface)) {
            Ok(h) => {
                c.handshake = Some(h);
                (TransferState::Connecting(c), Wake::Again)
            }
            Err(_) => (
                TransferState::Connecting(c).fail(ErrorKind::OutOfMemory),
                Wake::Again,
            ),
        },
        Err(kind) => (TransferState::Connecting(c).fail(kind), Wake::Again),
    }
}

/// The connection is set up (`conn_connect_trace`): timed and traced.
fn up<H: Host>(
    c: Connecting,
    cx: &mut StepCx<'_, H>,
    remote: SocketAddr,
    local: Option<SocketAddr>,
    at: Instant,
) -> (TransferState, Wake) {
    cx.report_mut().timings_mut().mark(Timer::Connect, at);
    cx.report_mut().set_primary(Ends { remote, local });
    // `CURL_CONN_HOST_DISPNAME`.
    let host = Bytes(c.route.destination().shown());
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

/// Why the setup failed, as C traces it (`cf_tcp_connect`,
/// `is_connected`).
fn connect_failed<H: Host>(cx: &mut StepCx<'_, H>, route: &Tcp, e: ConnectError) -> ErrorKind {
    // The peer connected to: the first proxy, else what a connect-to
    // names in the origin's place, else the origin
    // (`Curl_conn_get_first_peer`).
    let first = route.destination();
    // The proxy named in a failure: the SOCKS one when there are two
    // (`socks_proxy` before `http_proxy`), which is the first.
    let proxy = route.proxy.as_ref().map(ProxyRoute::first_peer);
    match e {
        ConnectError::OutOfMemory => return ErrorKind::OutOfMemory,
        ConnectError::Unresolved(why) => {
            // The name looked up is the first peer's: with a proxy, the
            // first proxy's.
            let (host, port) = (Bytes(first.name()), first.port());
            let (what, kind) = match proxy {
                Some(_) => ("proxy", ErrorKind::CouldntResolveProxy),
                None => ("host", ErrorKind::CouldntResolveHost),
            };
            // The reference build's resolver, c-ares, gives its reason
            // (`ares_strerror`), then fails again without it.
            let reason = match why {
                Unresolved::Resolver(ResolveFailure::NotFound) => Some("Domain name not found"),
                Unresolved::Resolver(ResolveFailure::NoData) => {
                    Some("DNS server returned answer with no data")
                }
                _ => None,
            };
            if why == Unresolved::Negative {
                trace::info(cx, format_args!("Negative DNS entry"));
            }
            let kind = match reason {
                Some(reason) => {
                    let first = format_args!("Could not resolve {what}: {host} ({reason})");
                    let kind = trace::fail(cx, kind, first);
                    trace::fail(cx, kind, format_args!("Could not resolve {what}: {host}"))
                }
                None => trace::fail(cx, kind, format_args!("Could not resolve {what}: {host}")),
            };
            trace::info(cx, format_args!("Could not resolve: {host}:{port}"));
            if why == Unresolved::Negative {
                trace::info(cx, format_args!("Could not resolve: {host}"));
            }
            return kind;
        }
        ConnectError::Failed(failure) => trace_failure(cx, failure),
    }
    let origin = &*route.origin;
    let (host, port) = (Bytes(origin.name()), origin.port());
    // A peer that is neither the origin nor the proxy named is shown.
    let via = Via(Some(first).filter(|&f| f != origin && Some(f) != proxy));
    let over = OverProxy(proxy);
    let ms = cx.easy().report().timings().since_single_ms(cx.rest.now);
    trace::fail(
        cx,
        ErrorKind::CouldntConnect,
        format_args!(
            "Failed to connect to {host}:{port}{via} {over}after {ms} ms: Could not connect to server"
        ),
    )
}

/// The proxy connected through, as a failure names it.
struct OverProxy<'a>(Option<&'a Peer>);

impl std::fmt::Display for OverProxy<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.0 {
            Some(peer) => write!(f, "over proxy {} ", Bytes(peer.name())),
            None => Ok(()),
        }
    }
}

/// The peer connected to in place of the origin, as a failure names it.
struct Via<'a>(Option<&'a Peer>);

impl std::fmt::Display for Via<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.0 {
            Some(peer) => write!(f, " via {}:{}", Bytes(peer.name()), peer.port()),
            None => Ok(()),
        }
    }
}

/// How an attempt failed, as C traces it.
fn trace_failure<H: Host>(cx: &mut StepCx<'_, H>, failure: Failure) {
    match failure {
        Failure::Immediate {
            remote,
            scope_found,
            error,
        } => {
            // The socket was opened, and traced, before its connect failed;
            // it never got a local address (`cf_tcp_connect`).
            trace_trying(cx, remote, scope_found);
            let why = OsError(&error);
            trace::info(
                cx,
                format_args!("Immediate connect fail for {}: {why}", remote.ip()),
            );
            let unbound = match remote {
                SocketAddr::V4(_) => IpAddr::from(std::net::Ipv4Addr::UNSPECIFIED),
                SocketAddr::V6(_) => IpAddr::from(std::net::Ipv6Addr::UNSPECIFIED),
            };
            trace::info(
                cx,
                format_args!(
                    "connect to {} port {} from {unbound} port 0 failed: {why}",
                    remote.ip(),
                    remote.port()
                ),
            );
        }
        Failure::Attempt {
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
}

/// An attempt to `remote` starts (`cf_socket_open`): after the scope it
/// took from a local interface, if it did, and with the scope it has.
fn trace_trying<H: Host>(
    cx: &mut StepCx<'_, H>,
    remote: SocketAddr,
    scope_found: Option<NonZeroU32>,
) {
    if let Some(scope) = scope_found {
        trace::info(
            cx,
            format_args!("determined scope_id={scope} for link-local address from local interface"),
        );
    }
    match remote {
        SocketAddr::V4(_) => trace::info(cx, format_args!("  Trying {remote}...")),
        SocketAddr::V6(v6) if v6.scope_id() != 0 => {
            let (ip, port, scope) = (v6.ip(), v6.port(), v6.scope_id());
            trace::info(
                cx,
                format_args!("  Trying [{ip}]:{port} scope_id={scope}..."),
            );
        }
        SocketAddr::V6(v6) => {
            trace::info(cx, format_args!("  Trying [{}]:{}...", v6.ip(), v6.port()));
        }
    }
}

/// The addresses a name resolved to, each family on a line of its own
/// (`cf_dns_report`), under the name it was found for; nothing for an
/// address the URL names.
fn report_answer<H: Host>(cx: &mut StepCx<'_, H>, c: &Connecting) {
    let Some(answer) = c.lease.answer() else {
        return;
    };
    report_resolved(cx, &answer, c.route.destination().port());
}

/// As `report_answer`, for `answer`, found for port `port`.
fn report_resolved<H: Host>(cx: &mut StepCx<'_, H>, answer: &Answer, port: u16) {
    if !answer.resolved() {
        return;
    }
    let host = Bytes(answer.name());
    trace::info(cx, format_args!("Host {host}:{port} was resolved."));
    trace::info(cx, format_args!("IPv6: {}", Family(answer.addrs(), true)));
    trace::info(cx, format_args!("IPv4: {}", Family(answer.addrs(), false)));
}

/// The addresses of one family, IPv6 if `1`, comma-separated; `(none)`
/// for none.
struct Family<'a>(&'a [IpAddr], bool);

impl std::fmt::Display for Family<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut of = self.0.iter().filter(|a| a.is_ipv6() == self.1);
        let Some(first) = of.next() else {
            return f.write_str("(none)");
        };
        first.fmt(f)?;
        of.try_for_each(|a| write!(f, ", {a}"))
    }
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

/// An operating system error as `strerror` words it, made without
/// allocating, as C's `curlx_strerror` writes it into a buffer on the
/// stack.
pub(crate) struct OsError<'a>(pub(crate) &'a std::io::Error);

impl std::fmt::Display for OsError<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        Bytes(curl_os::error::ErrorText::of(self.0).as_bytes()).fmt(f)
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

/// C's pretransfer, once per transfer: the option's URL parsed for the
/// first request.
fn pretransfer<H: Host>(run: &mut Run, cx: &mut StepCx<'_, H>) -> Result<Url, ErrorKind> {
    #[cfg(feature = "debug-hooks")]
    if std::mem::take(&mut run.warn) {
        trace::info(cx, format_args!("!!! WARNING !!!"));
        trace::info(
            cx,
            format_args!("This is a debug build of libcurl, do not use in production."),
        );
    }
    // The application's own URL goes first, as it is now: one that
    // cannot be read back is none (`Curl_pretransfer`).
    let shared = cx.easy().options().shared_url().map(|shared| {
        shared.with(|url| {
            let readable = url.get(Part::Url, GetOptions::NONE).is_ok();
            (readable, url.try_clone())
        })
    });
    let unset = match &shared {
        Some((readable, _)) => !readable,
        None => cx.easy().options().url().is_none(),
    };
    if unset {
        return Err(trace::fail(
            cx,
            ErrorKind::UrlMalformat,
            format_args!("No URL set"),
        ));
    }
    run.retries = 0;
    run.inherited = Inherited::new(cx.easy().options().method);
    let options = cx.easy().options();
    let (want, proxy_want) = (options.http.auth.0, options.proxy.auth.0);
    cx.easy_mut().auth.start(want, proxy_want);
    // The application's referer, until a redirect gives another.
    if let Some(given) = &cx.easy().options().http.referer {
        let mut referer = Vec::new();
        referer
            .try_extend_from_slice(given)
            .map_err(|_| ErrorKind::OutOfMemory)?;
        cx.report_mut().set_referer(referer);
    }
    cx.mark(Timer::StartOp);
    crate::proto::http::cookies::load(cx)?;
    read_resolve(cx)?;
    // Taken as it is parsed, its text not read again.
    if let Some((_, copy)) = shared {
        return copy.map_err(url_error);
    }
    let options = cx.easy().options();
    match parse_url(options.url().expect("checked above"), options) {
        Ok(url) => Ok(url),
        Err(UrlRefused::Rejected(e)) => Err(trace::fail(
            cx,
            url_error(e),
            format_args!("URL rejected: {e}"),
        )),
        Err(UrlRefused::Failed(kind)) => Err(kind),
    }
}

/// Read the application's resolve list into the multi's cache, once for
/// each time it is set (`Curl_loadhostpairs`): a list the cache cannot
/// take is read again by the next transfer.
fn read_resolve<H: Host>(cx: &mut StepCx<'_, H>) -> Result<(), ErrorKind> {
    if cx.easy().options().resolve.stamp() == cx.easy().resolve_read {
        return Ok(());
    }
    // As the application's source has it now.
    cx.easy_mut()
        .options_mut()
        .resolve
        .refill()
        .map_err(|_| ErrorKind::OutOfMemory)?;
    // A copy is read, as the cache and the trace are reached while it is:
    // the debug handler may set the list. Read whole, the list is done
    // with, and so is one set meanwhile, as C clears `state.resolve`
    // once it has read the old one; one that failed is read again.
    let entries = cx
        .easy()
        .options()
        .resolve
        .try_clone()
        .map_err(|OutOfMemory| ErrorKind::OutOfMemory)?;
    let read = read_entries(cx, &entries);
    if read.is_ok() {
        cx.easy_mut().resolve_read = cx.easy().options().resolve.stamp();
    }
    read
}

fn read_entries<H: Host>(cx: &mut StepCx<'_, H>, list: &ResolveList) -> Result<(), ErrorKind> {
    if list.entries().next().is_none() {
        return Ok(());
    }
    cx.easy_mut().wildcard_resolve = false;
    let now = cx.rest.now;
    for line in list.entries() {
        let (name, port, addrs, permanent, given) = match parse_entry(line) {
            Ok(None) => continue,
            Ok(Some(ListEntry::Remove { name, port })) => {
                let kept = cx.rest.kept(cx.me, Kind::Names);
                let (_, mut names) = cx.rest.net_names(cx.me, kept.as_ref());
                names.section(|dns| dns.remove(name, port));
                continue;
            }
            Ok(Some(ListEntry::Add {
                name,
                port,
                addrs,
                permanent,
                given,
            })) => (name, port, addrs, permanent, given),
            Err(BadEntry::OutOfMemory) => return Err(ErrorKind::OutOfMemory),
            Err(BadEntry::Syntax { illegal }) => {
                if let Some(ip) = illegal {
                    let ip = Bytes(ip);
                    trace::info(
                        cx,
                        format_args!("Resolve IP address '{ip}' found is illegal"),
                    );
                }
                let kind = ErrorKind::SetoptOptionSyntax;
                let line = Bytes(line);
                let why = format_args!("Could not parse CURLOPT_RESOLVE entry '{line}'");
                return Err(trace::fail(cx, kind, why));
            }
        };
        let answer = Answer::new(name, addrs).map_err(|OutOfMemory| ErrorKind::OutOfMemory)?;
        let answer = TryArc::try_new(answer).map_err(|OutOfMemory| ErrorKind::OutOfMemory)?;
        // One use of the names, the old answer discarded and the new kept
        // (`Curl_loadhostpairs`).
        let kept = cx.rest.kept(cx.me, Kind::Names);
        let (_, mut names) = cx.rest.net_names(cx.me, kept.as_ref());
        let (discarded, put) = names.section(|dns| {
            let discarded = dns.remove(name, port);
            (discarded, dns.put(answer, port, now, permanent))
        });
        if discarded {
            let name = Bytes(name);
            trace::info(
                cx,
                format_args!("RESOLVE {name}:{port} - old addresses discarded"),
            );
        }
        put.map_err(|OutOfMemory| ErrorKind::OutOfMemory)?;
        let (shown, given) = (Bytes(name), Bytes(given));
        let kept = if permanent { "" } else { " (non-permanent)" };
        trace::info(
            cx,
            format_args!("[DNS] added {shown}:{port}:{given} to cache{kept}"),
        );
        if name == b"*" {
            trace::info(cx, format_args!("RESOLVE *:{port} using wildcard"));
            cx.easy_mut().wildcard_resolve = true;
        }
    }
    Ok(())
}

/// What follows a complete exchange: the redirect it is to follow, or
/// none, where a `Location:` would have led kept for the application, as
/// C's `FOLLOW_FAKE` keeps it at the end of the exchange.
fn after_exchange<H: Host>(
    run: &mut Run,
    x: &mut Attached,
    cx: &mut StepCx<'_, H>,
) -> Result<AfterRequest, ErrorKind> {
    // A 417 has the request made again without `Expect`, as a redirect
    // to its own URL.
    if x.proto.expect_refused() {
        run.inherited.no_expect = true;
        let mut location = Vec::new();
        location
            .try_extend_from_slice(&run.url)
            .map_err(|_| ErrorKind::OutOfMemory)?;
        return Ok(AfterRequest::Follow {
            location,
            code: 417,
        });
    }
    // A 401 or 407 whose challenge the request can answer has it made
    // again.
    if let Some(Challenged {
        offered,
        act,
        code,
        origin,
    }) = x.proto.auth()
    {
        let report = cx.report_mut();
        report.add_auth_offered(offered.host.offered);
        report.add_proxy_auth_offered(offered.proxy.offered);
        if let Some(picked) = act.picked.filter(|p| !p.is_empty()) {
            report.set_auth_used(picked);
        }
        if let Some(picked) = act.proxy_picked.filter(|p| !p.is_empty()) {
            report.set_proxy_auth_used(picked);
        }
        // The proxy's challenge is kept for the proxy, which is the
        // connection's origin when the request went to it whole.
        let proxy = x.origin.as_deref().expect("an HTTP request has an origin");
        cx.easy_mut()
            .auth
            .apply(&act, offered, origin, proxy)
            .map_err(|OutOfMemory| ErrorKind::OutOfMemory)?;
        if act.reload {
            let mut location = Vec::new();
            location
                .try_extend_from_slice(&run.url)
                .map_err(|_| ErrorKind::OutOfMemory)?;
            return Ok(AfterRequest::Follow { location, code });
        }
    }
    if let Some((location, code)) = x.proto.follow() {
        let mut copy = Vec::new();
        copy.try_extend_from_slice(location)
            .map_err(|_| ErrorKind::OutOfMemory)?;
        return Ok(AfterRequest::Follow {
            location: copy,
            code,
        });
    }
    if let Some(location) = x.proto.location() {
        keep_redirect_url(run, cx, location)?;
    }
    Ok(AfterRequest::Complete)
}

/// The URL of the request just made, as it was parsed for it (C's
/// `state.uh`).
fn request_url<H: Host>(run: &Run, cx: &StepCx<'_, H>) -> Result<Url, ErrorKind> {
    let mut url = match parse_url(&run.url, cx.easy().options()) {
        Ok(url) => url,
        Err(UrlRefused::Rejected(e)) => return Err(url_error(e)),
        Err(UrlRefused::Failed(kind)) => return Err(kind),
    };
    apply_port(&mut url, run, cx);
    Ok(url)
}

/// The application's port set over `url`'s, unless a redirect took it
/// away (`Curl_peer_from_url`'s `port_override`).
fn apply_port<H: Host>(url: &mut Url, run: &Run, cx: &StepCx<'_, H>) {
    if let Some(port) = cx
        .easy()
        .options()
        .port
        .filter(|_| run.inherited.allow_port)
    {
        url.set_port(port);
    }
}

/// Where `location` would have led from the request, kept for the
/// application (`follow_fake`).
fn keep_redirect_url<H: Host>(
    run: &Run,
    cx: &mut StepCx<'_, H>,
    location: &[u8],
) -> Result<(), ErrorKind> {
    let base = request_url(run, cx)?;
    let path_as_is = cx.easy().options().url_rules.path_as_is;
    let url = follow::would_redirect(base, location, path_as_is)?;
    cx.report_mut().set_redirect_url(url);
    Ok(())
}

/// A redirect is followed (`Curl_http_follow`, `FOLLOW_REDIR`): counted,
/// `location` resolved against the request's URL, and a leg started for
/// it. Past the limit, where it leads is kept and the transfer fails.
fn follow_leg<H: Host>(
    run: &mut Run,
    cx: &mut StepCx<'_, H>,
    proto: &mut ProtoState,
    location: &[u8],
    code: u16,
) -> TransferState {
    let options = cx.easy().options();
    let path_as_is = options.url_rules.path_as_is;
    let max = options.http.max_redirects.0;
    let base = match request_url(run, cx) {
        Ok(base) => base,
        Err(e) => return TransferState::Init.fail(e),
    };
    if let Some(max) = max
        && cx.report_mut().redirects() >= u32::from(max)
    {
        if let Err(e) = keep_redirect_url(run, cx, location) {
            return TransferState::Init.fail(e);
        }
        let why = format_args!("Maximum ({max}) redirects followed");
        return TransferState::Init.fail(trace::fail(cx, ErrorKind::TooManyRedirects, why));
    }
    cx.report_mut().count_redirect();
    if cx.easy().options().http.auto_referer {
        match referer_of(&run.url) {
            Ok(referer) => cx.report_mut().set_referer(referer),
            Err(e) => return TransferState::Init.fail(e),
        }
    }
    let url = match follow::resolve(base, location, path_as_is) {
        Ok(url) => url,
        Err(e) => {
            let kind = url_error(e);
            let why = format_args!("The redirect target URL could not be parsed: {e}");
            return TransferState::Init.fail(trace::fail(cx, kind, why));
        }
    };
    // An absolute URL is reached on its own port, unless the code asks
    // for credentials.
    if !matches!(code, 401 | 407) && url::is_absolute(location) {
        run.inherited.allow_port = false;
    }
    let text = match url.get(Part::Url, GetOptions::NONE) {
        Ok(text) => text,
        Err(e) => return TransferState::Init.fail(url_error(e)),
    };
    // The body is started over before anything else is said of the next
    // request (`Curl_req_soft_reset`); a failure stands only if the next
    // request would send it.
    let rewound = proto.rewind_upload(cx);
    let shown = Bytes(&text);
    trace::info(
        cx,
        format_args!("Issue another request to this URL: '{shown}'"),
    );
    let http = &cx.easy().options().http;
    let custom = http.custom_method.is_some();
    if http.follow == Follow::FirstOnly && custom && !run.inherited.ignore_custom {
        run.inherited.ignore_custom = true;
        trace::info(
            cx,
            format_args!("Drop custom request method for next request"),
        );
    }
    let http = &cx.easy().options().http;
    let switched = follow::switches_to_get(code, run.inherited.method, http.post_redirect);
    if switched {
        switch_to_get(run, cx, code);
    }
    if let Err(e) = rewound
        && !switched
    {
        return TransferState::Init.fail(e);
    }
    // Parsed again for its leg, as every request's URL is.
    let url = match parse_url(&text, cx.easy().options()) {
        Ok(url) => url,
        Err(UrlRefused::Rejected(e)) => {
            let why = format_args!("URL rejected: {e}");
            return TransferState::Init.fail(trace::fail(cx, url_error(e), why));
        }
        Err(UrlRefused::Failed(kind)) => return TransferState::Init.fail(kind),
    };
    next_leg(run, cx, url)
}

/// A request is to be made again: its URL parsed anew, as the follow of a
/// retry does (`Curl_http_follow`, `FOLLOW_RETRY`), and a leg started.
fn retry_leg<H: Host>(
    run: &mut Run,
    cx: &mut StepCx<'_, H>,
    proto: &mut ProtoState,
) -> TransferState {
    let url = match parse_url(&run.url, cx.easy().options()) {
        Ok(url) => url,
        Err(UrlRefused::Rejected(e)) => {
            let kind = url_error(e);
            let why = format_args!("The redirect target URL could not be parsed: {e}");
            return TransferState::Init.fail(trace::fail(cx, kind, why));
        }
        Err(UrlRefused::Failed(kind)) => return TransferState::Init.fail(kind),
    };
    let shown = match url.get(Part::Url, GetOptions::NONE) {
        Ok(shown) => shown,
        Err(e) => return TransferState::Init.fail(url_error(e)),
    };
    // As for a redirect, which never switches to GET here.
    let rewound = proto.rewind_upload(cx);
    let shown = Bytes(&shown);
    trace::info(
        cx,
        format_args!("Issue another request to this URL: '{shown}'"),
    );
    if let Err(e) = rewound {
        return TransferState::Init.fail(e);
    }
    next_leg(run, cx, url)
}

/// `url`, a request's, without credentials or fragment, as the referer
/// of the redirect it got (`set_auto_referer`); C takes any failure for
/// a lack of memory.
fn referer_of(url: &[u8]) -> Result<Vec<u8>, ErrorKind> {
    let none = SetOptions::NONE;
    let mut url = Url::parse(url, ParseOptions::NONE).map_err(|_| ErrorKind::OutOfMemory)?;
    url.set(Part::Fragment, None, none)
        .and_then(|()| url.set(Part::User, None, none))
        .and_then(|()| url.set(Part::Password, None, none))
        .and_then(|()| url.get(Part::Url, GetOptions::NONE))
        .map_err(|_| ErrorKind::OutOfMemory)
}

/// The next request asks for a GET (`http_switch_to_get`): traced and the
/// custom method dropped only if the redirect's code is obeyed.
fn switch_to_get<H: Host>(run: &mut Run, cx: &mut StepCx<'_, H>, code: u16) {
    let http = &cx.easy().options().http;
    let custom = http.custom_method.as_deref();
    let inherited = &mut run.inherited;
    // Formatted before it is traced, as the debug handler may set the
    // custom method, and the next request uses what it sets.
    let said = if (custom.is_some() || inherited.method != Method::Get)
        && http.follow == Follow::ObeyCode
    {
        inherited.ignore_custom = true;
        Some(trace::line(format_args!(
            "Switch to GET because of {code} response"
        )))
    } else if let Some(custom) = custom
        && http.follow != Follow::FirstOnly
    {
        let custom = Bytes(custom);
        Some(trace::line(format_args!(
            "Stick to {custom} instead of GET"
        )))
    } else {
        None
    };
    if let Some(said) = said {
        trace::info_line(cx, &said);
    }
    // A HEAD stays bodyless, as `CURLOPT_NOBODY` keeps it.
    if run.inherited.method != Method::Head {
        run.inherited.method = Method::Get;
    }
}

/// The next request of a transfer, made again or redirected, for `url`:
/// counted in the header store, timed, and its leg started.
fn next_leg<H: Host>(run: &mut Run, cx: &mut StepCx<'_, H>, url: Url) -> TransferState {
    cx.report_mut().headers_mut().next_request();
    cx.mark(Timer::Redirect);
    // The sizes to come are the new request's (`Curl_pgrsResetTransferSizes`).
    let sizes = cx.report_mut().sizes_mut();
    sizes.download_expected = None;
    sizes.upload_expected = None;
    start_leg(run, cx, url)
}

/// Whether a request that got nothing back over a reused connection is
/// made again on a fresh one (`Curl_retry_request`): the connection may
/// have closed as it was reused. The fifth retry fails the transfer.
fn retry_request<H: Host>(
    run: &mut Run,
    x: &mut Attached,
    cx: &mut StepCx<'_, H>,
) -> Result<bool, ErrorKind> {
    if !x.proto.retryable() || !x.lease.conn().reused() {
        return Ok(false);
    }
    if run.retries >= MAX_RETRIES {
        run.retries = 0;
        return Err(trace::fail(
            cx,
            ErrorKind::SendError,
            format_args!("Connection died, tried {MAX_RETRIES} times before giving up"),
        ));
    }
    run.retries += 1;
    let count = run.retries;
    trace::info(
        cx,
        format_args!("Connection died, retrying a fresh connect (retry count: {count})"),
    );
    x.lease.get().mark_close();
    Ok(true)
}

/// C's SETUP and CONNECT, which always run in one pass, for each request
/// of a transfer: the leg's timers, the protocol and a connection for
/// `url`, then the protocol connects over it.
fn start_leg<H: Host>(run: &mut Run, cx: &mut StepCx<'_, H>, mut url: Url) -> TransferState {
    run.deadlines.start_leg(cx.rest.now);
    // Cookies are counted from nothing for each request
    // (`Curl_req_hard_reset`).
    cx.easy_mut().set_cookies = 0;
    // The connect-to entries as the application's source has them now,
    // as C walks them for each connection it sets up; the header lists
    // are read as the request is built.
    if let Err(OutOfMemory) = cx.easy_mut().options_mut().connect_to.refill() {
        return TransferState::Init.fail(ErrorKind::OutOfMemory);
    }
    cx.report_mut().set_method(run.inherited.method);
    cx.mark(Timer::StartSingle);
    cx.mark(Timer::PostQueue);
    // Counted from nothing for each request (`Curl_init_do`).
    let (speedometer, report) = cx.progress_parts();
    report.sizes_mut().new_request();
    speedometer.start_over();
    // Read back once parsed, credentials and all, as C reads it back
    // (`url.c`, `CURLUPART_URL` into `state.url`): one that cannot be,
    // grown past the limit, fails the transfer without a word. It is read
    // before the application's port is applied, so the URL traced,
    // reported and sent as a referer is the one asked for; were HSTS to
    // upgrade it, C would read it back again, port and all.
    let get = GetOptions {
        get_empty: true,
        ..GetOptions::NONE
    };
    match url.get(Part::Url, get) {
        Ok(whole) => run.url = whole,
        Err(e) => return TransferState::Init.fail(url_error(e)),
    }
    // The transfer's URL from here on is the report's, whatever fails.
    if let Err(OutOfMemory) = cx.report_mut().set_url(&url) {
        return TransferState::Init.fail(ErrorKind::OutOfMemory);
    }
    // The application's port over the URL's, where the request goes and
    // what a relative redirect resolves against (`Curl_peer_from_url`
    // sets it in `state.uh`).
    apply_port(&mut url, run, cx);
    let scheme = match url.get(Part::Scheme, GetOptions::NONE) {
        Ok(s) => s,
        Err(e) => return TransferState::Init.fail(url_error(e)),
    };
    // Known before the protocol opens anything, as C records it.
    cx.report_mut().set_protocol(Protocol::of_scheme(&scheme));
    // A redirect goes only where C's `CURLPROTO_REDIR` lets it
    // (`url_set_conn_scheme`).
    let redirected = cx.report_mut().redirects() > 0;
    let refused = redirected && !matches!(&scheme[..], b"http" | b"https" | b"ftp" | b"ftps");
    let started = if refused {
        Ok(None)
    } else {
        ProtoState::start(&scheme, &url, &run.inherited, cx)
    };
    let proto = match started {
        Ok(Some(proto)) => proto,
        Ok(None) => {
            // A scheme libcurl knows is one this build leaves out.
            let why: &[u8] = if url::is_known_scheme(&scheme) {
                b"\" is disabled"
            } else {
                b"\" not supported"
            };
            let follow: &[u8] = if redirected { b" (in redirect)" } else { b"" };
            let kind = ErrorKind::UnsupportedProtocol;
            let kind = trace::fail_with(cx, kind, &[b"Protocol \"", &scheme, why, follow]);
            return TransferState::Init.fail(kind);
        }
        Err(e) => return TransferState::Init.fail(e),
    };
    // A host name may be no longer than C lets a URL be (`MAX_URL_LEN`,
    // `Curl_peer_from_url`).
    if url.host_held().is_some_and(|host| host.len() > MAX_HOST) {
        let kind = ErrorKind::UrlMalformat;
        let kind = trace::fail_with(cx, kind, &[b"Too long hostname (maximum is 65535)"]);
        return TransferState::Init.fail(kind);
    }
    let target = proto.network(&url, cx.easy().options().address_scope);
    let target = match target {
        Ok(Some(target)) => target,
        Ok(None) => {
            let lease = match acquire(cx, Route::Local) {
                Ok(Acquired::New(lease)) => lease,
                Ok(Acquired::Reused(_)) => {
                    unreachable!("a connection without a network is never kept")
                }
                Ok(Acquired::Wait(_)) => {
                    unreachable!("a connection without a network has no limits")
                }
                Err(OutOfMemory) => return TransferState::Init.fail(ErrorKind::OutOfMemory),
            };
            // A connection without a network has its name at once.
            cx.mark(Timer::NameLookup);
            return TransferState::ProtoConnect(Attached {
                lease,
                proto,
                origin: None,
            });
        }
        Err(e) => return TransferState::Init.fail(e),
    };
    let Ok(origin) = TryArc::try_new(target) else {
        return TransferState::Init.fail(ErrorKind::OutOfMemory);
    };
    if run.inherited.first.is_none() {
        run.inherited.first = Some(origin.clone());
    }
    let via = match connect_to(cx, &origin) {
        Ok(via) => via,
        Err(e) => return TransferState::Init.fail(e),
    };
    let proxy = match choose_proxy(cx, &origin, &scheme, via.is_some()) {
        Ok(proxy) => proxy,
        Err(e) => return TransferState::Init.fail(e),
    };
    // A request a proxy sends on names the whole URL, and the connection
    // is the proxy's (`origin_is_proxy`).
    let mut proto = proto;
    let origin = match &proxy {
        Some(p) if p.forward => {
            if let Err(e) = proto.forward(&url) {
                return TransferState::Init.fail(e);
            }
            p.peer.clone()
        }
        _ => origin,
    };
    let route = Tcp {
        origin,
        via,
        ip: cx.easy().options().ip_version,
        proxy,
    };
    setup(cx, Plan { proto, route })
}

/// The proxy the transfer to `origin` goes through, if any
/// (`Curl_proxy_init_conn`): the options', or else the one the
/// environment names for `scheme`, unless the no-proxy list names the
/// origin's host; behind the SOCKS pre-proxy if one is set, which alone
/// is the proxy. Through a connect-to peer (`via`), an HTTP proxy would
/// tunnel.
fn choose_proxy<H: Host>(
    cx: &mut StepCx<'_, H>,
    origin: &Peer,
    scheme: &[u8],
    via: bool,
) -> Result<Option<ProxyRoute>, ErrorKind> {
    let options = &cx.easy().options().proxy;
    let no_proxy = match &options.no_proxy {
        Some(list) => Some(copied(list)?),
        None => env_named(cx, &[b"no_proxy", b"NO_PROXY"])?,
    };
    if no_proxy.is_some_and(|list| proxy::excluded(origin.name(), &list)) {
        return Ok(None);
    }
    let options = &cx.easy().options().proxy;
    // An empty one is none, and turns the environment's off too.
    let given = |text: Option<&[u8]>| text.filter(|t| !t.is_empty()).map(copied).transpose();
    let detect = !matches!(options.url.as_deref(), Some([]))
        && !matches!(options.pre_proxy.as_deref(), Some([]));
    let pre = given(options.pre_proxy.as_deref())?;
    let text = match given(options.url.as_deref())? {
        Some(text) => Some(text),
        None if pre.is_some() || !detect => None,
        None => match proxy::detect(scheme, &mut getenv).map_err(|_| ErrorKind::OutOfMemory)? {
            Some(found) => {
                let name = found.name();
                let said: [&[u8]; 5] = [
                    b"Uses proxy env variable ",
                    name,
                    b" == '",
                    &found.value,
                    b"'",
                ];
                trace::info_with(cx, &said);
                Some(found.value)
            }
            None => None,
        },
    };
    let pre = match pre {
        Some(pre) => Some(parse_proxy(cx, &pre, true)?),
        None => None,
    };
    let auth_only = cx.easy().options().proxy.socks5_auth.only;
    let Some(text) = text else {
        // The pre-proxy alone is the SOCKS proxy.
        return Ok(
            pre.map(|(kind, peer, creds)| ProxyRoute::new(kind, peer, creds, false, auth_only))
        );
    };
    let (kind, peer, creds) = parse_proxy(cx, &text, false)?;
    // Through a SOCKS proxy, the request goes as to the origin.
    if crate::conn::socks::Version::of(kind).is_some() {
        if pre.is_some() {
            return Err(trace::fail_with(
                cx,
                ErrorKind::CouldntResolveProxy,
                &[
                    b"Having a SOCKS pre-proxy and proxy is not supported with '",
                    &text,
                    b"'",
                ],
            ));
        }
        return Ok(Some(ProxyRoute::new(kind, peer, creds, false, auth_only)));
    }
    // A request goes to an HTTP proxy whole, unless it is asked to
    // tunnel, or reaches the origin through another peer; HTTP is the
    // only scheme here, and it is not secured.
    let tunnel = cx.easy().options().proxy.tunnel || via;
    let route = ProxyRoute::new(kind, peer, creds, !tunnel, auth_only);
    Ok(Some(match pre {
        Some((kind, peer, creds)) => route.behind(PreProxy { kind, peer, creds }),
        None => route,
    }))
}

/// A proxy's URL, `text`, as its type, its peer and its credentials
/// (`parse_proxy`): a pre-proxy is SOCKS4 unless its scheme says
/// otherwise, never HTTP, and has only the credentials its URL gives.
#[expect(clippy::type_complexity, reason = "the route's own parts")]
fn parse_proxy<H: Host>(
    cx: &mut StepCx<'_, H>,
    text: &[u8],
    pre: bool,
) -> Result<(ProxyType, TryArc<Peer>, Option<TryArc<ProxyCreds>>), ErrorKind> {
    let options = &cx.easy().options().proxy;
    let kind = if pre { ProxyType::Socks4 } else { options.kind };
    let parsed = match proxy::parse(text, kind, options.port) {
        Ok(parsed) => parsed,
        Err(Refused::OutOfMemory) => return Err(ErrorKind::OutOfMemory),
        Err(Refused::Syntax(e)) => {
            let text = Bytes(text);
            return Err(trace::fail(
                cx,
                ErrorKind::CouldntResolveProxy,
                format_args!("Unsupported proxy syntax in '{text}': {e}"),
            ));
        }
        Err(Refused::Scheme) => {
            return Err(trace::fail_with(
                cx,
                ErrorKind::CouldntConnect,
                &[b"Unsupported proxy scheme for '", text, b"'"],
            ));
        }
        Err(Refused::Credentials(e)) => return Err(url_error(e)),
        Err(Refused::Https) => {
            return Err(trace::fail_with(
                cx,
                ErrorKind::NotBuiltIn,
                &[
                    b"Unsupported proxy '",
                    text,
                    b"', libcurl is built without the HTTPS-proxy support.",
                ],
            ));
        }
    };
    if pre && crate::conn::socks::Version::of(parsed.kind).is_none() {
        return Err(trace::fail_with(
            cx,
            ErrorKind::CouldntResolveProxy,
            &[b"Unsupported pre-proxy type for '", text, b"'"],
        ));
    }
    // The URL's user and password, else the options' (`proxy_parse`).
    let options = &cx.easy().options().proxy;
    let (user, password) = match (parsed.user, parsed.password) {
        (None, None) if !pre => (
            options.user.as_deref().map(copied).transpose()?,
            options.password.as_deref().map(copied).transpose()?,
        ),
        given => given,
    };
    let creds = match (user, password) {
        (None, None) => None,
        (user, password) => Some(
            TryArc::try_new(ProxyCreds {
                user: user.unwrap_or_default(),
                password: password.unwrap_or_default(),
            })
            .map_err(|OutOfMemory| ErrorKind::OutOfMemory)?,
        ),
    };
    let peer = TryArc::try_new(parsed.peer).map_err(|OutOfMemory| ErrorKind::OutOfMemory)?;
    Ok((parsed.kind, peer, creds))
}

/// The first of the environment variables `names` set, traced as C
/// traces it.
fn env_named<H: Host>(
    cx: &mut StepCx<'_, H>,
    names: &[&[u8]],
) -> Result<Option<Vec<u8>>, ErrorKind> {
    for name in names {
        if let Some(value) = getenv(name).map_err(|_| ErrorKind::OutOfMemory)? {
            trace::info_with(
                cx,
                &[b"Uses proxy env variable ", name, b" == '", &value, b"'"],
            );
            return Ok(Some(value));
        }
    }
    Ok(None)
}

/// The environment variable `name`, unless unset or empty
/// (`curl_getenv`); `Err` when its copy cannot be allocated, where C's
/// reads as unset.
fn getenv(name: &[u8]) -> Result<Option<Vec<u8>>, OutOfMemory> {
    Ok(curl_os::env::var(name)?.filter(|value| !value.is_empty()))
}

fn copied(bytes: &[u8]) -> Result<Vec<u8>, ErrorKind> {
    let mut copy = Vec::new();
    copy.try_extend_from_slice(bytes)
        .map_err(|_| ErrorKind::OutOfMemory)?;
    Ok(copy)
}

/// A connection for the request (`Curl_connect`): one to set up, or an
/// idle one to reuse, or none while the multi's limits allow none, the
/// request waiting for one (`multistate_connect`).
fn setup<H: Host>(cx: &mut StepCx<'_, H>, plan: Plan) -> TransferState {
    let acquired = acquire(cx, Route::Tcp(plan.route.clone()));
    if !matches!(acquired, Ok(Acquired::Wait(_))) {
        // One waiting may now find room too.
        schedule_pending(&mut cx.rest);
    }
    let lease = match acquired {
        Ok(Acquired::New(lease)) => lease,
        Ok(Acquired::Reused(lease)) => {
            let route = &plan.route;
            let name = route.origin.scheme().name;
            let (to, host) = match &route.proxy {
                Some(proxy) => ("proxy", Bytes(proxy.peer.shown())),
                None => ("host", Bytes(route.origin.name())),
            };
            trace::info(
                cx,
                format_args!("Reusing existing {name}: connection with {to} {host}"),
            );
            lease
        }
        Ok(Acquired::Wait(reason)) => {
            match reason {
                WaitReason::HostLimit => {
                    trace::info(cx, format_args!("No more connections allowed to host"));
                }
                WaitReason::TotalLimit(max) => trace::info(
                    cx,
                    format_args!("No connections available, total of {max} reached."),
                ),
            }
            return TransferState::Pending(plan);
        }
        Err(OutOfMemory) => return TransferState::Init.fail(ErrorKind::OutOfMemory),
    };
    cx.report_mut().set_used_proxy(plan.route.proxy.is_some());
    let Plan { proto, route } = plan;
    TransferState::Connecting(Connecting {
        lease,
        proto,
        route,
        handshake: None,
    })
}

/// Let the next transfer waiting for a connection, after the last one
/// let, look for one again (`multi_schedule_pending`): one at a time, as
/// a connection freed most often makes room for one.
pub(crate) fn schedule_pending<H: Host>(rest: &mut EngineRest<'_, H>) {
    wake_pending(rest.tell.slots, rest.dirty, rest.pending_after);
}

/// As `schedule_pending`, on the multi's tables.
pub(super) fn wake_pending<H: Host>(
    slots: &mut Slots<H>,
    dirty: &mut RowSet,
    after: &mut Option<TransferId>,
) {
    let waiting = |slots: &Slots<H>, id| {
        slots
            .get(id)
            .and_then(|slot| slot.run.as_ref())
            .is_some_and(|run| matches!(run.state, TransferState::Pending(_)))
    };
    // From the one after the last let, round to the start.
    let mut found = None;
    let mut cursor = *after;
    while let Some(id) = slots.next_after(cursor) {
        cursor = Some(id);
        if waiting(slots, id) {
            found = Some(id);
            break;
        }
    }
    if found.is_none() {
        let mut cursor = None;
        while let Some(id) = slots.next_after(cursor) {
            cursor = Some(id);
            if waiting(slots, id) {
                found = Some(id);
                break;
            }
        }
    }
    let Some(id) = found else {
        return;
    };
    let run = slots
        .get_mut(id)
        .and_then(|slot| slot.run.as_mut())
        .expect("found waiting");
    let TransferState::Pending(plan) = std::mem::replace(&mut run.state, TransferState::Init)
    else {
        unreachable!("found waiting");
    };
    run.state = TransferState::Setup(plan);
    dirty.insert(id.index());
    *after = Some(id);
}

/// The peer the connect-to entries send a connection for `origin` to, if
/// not `origin` itself (`url_set_conn_peer`).
fn connect_to<H: Host>(
    cx: &mut StepCx<'_, H>,
    origin: &Peer,
) -> Result<Option<TryArc<Peer>>, ErrorKind> {
    // The reason formatted while the entries are borrowed, and given once
    // they are not: the debug handler may set them.
    let (kind, reason) = match crate::conn::via(origin, cx.easy().options().connect_to.iter()) {
        Ok(None) => return Ok(None),
        Ok(Some(via)) => {
            return TryArc::try_new(via)
                .map(Some)
                .map_err(|OutOfMemory| ErrorKind::OutOfMemory);
        }
        Err(BadVia::OutOfMemory) => return Err(ErrorKind::OutOfMemory),
        Err(BadVia::Syntax { kind, why, text }) => {
            let text = Bytes(text);
            (kind, trace::reason(format_args!("{why} in '{text}'")))
        }
    };
    Err(trace::fail_for(cx, kind, reason))
}

/// A connection for the transfer, and the trace of what the search for
/// one did.
fn acquire<H: Host>(cx: &mut StepCx<'_, H>, route: Route) -> Result<Acquired, OutOfMemory> {
    let limits = cx.easy().options().limits.reuse;
    let rules = ReuseRules {
        max_idle: limits.max_idle.map(TimeLimit::duration),
        max_age: limits.max_age.map(TimeLimit::duration),
        // A redirect's request would reuse one anyway.
        fresh: limits.fresh,
    };
    let mut notes = Vec::new();
    let now = cx.rest.now;
    let add = cx.rest.tell.limits.add();
    // The search and the addition, each a use of the pool of its own
    // (`Curl_cpool_find`, `Curl_cpool_add`).
    let home = cx.rest.kept(cx.me, Kind::Connections).map(|k| k.share);
    let found = if pool::searches(&route, rules) {
        cx.rest.pool_section(cx.me, home.as_ref(), |pool, net| {
            pool.find(&route, rules, net, now, &mut notes)
        })?
    } else {
        None
    };
    let mut acquired = match found {
        Some(lease) => Acquired::Reused(lease),
        None => cx.rest.pool_section(cx.me, home.as_ref(), |pool, net| {
            pool.add(route, add, net, now)
        })?,
    };
    if let (Some(share), Acquired::Reused(lease) | Acquired::New(lease)) = (home, &mut acquired) {
        lease.set_home(share);
    }
    // The transfer's connection from now on (`Curl_attach_connection`).
    if let Acquired::Reused(lease) | Acquired::New(lease) = &acquired {
        cx.report_mut().set_conn(Some(lease.number()));
    }
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

/// A request's URL, parsed by the options' rules, given the default
/// scheme where it has none (`parseurlandfillconn`).
fn parse_url(url: &[u8], options: &Options) -> Result<Url, UrlRefused> {
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
        let url = parse_url(url.as_bytes(), &options).map_err(|e| match e {
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
