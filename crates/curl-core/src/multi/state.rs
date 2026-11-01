//! A transfer's states and the steps between them (`multi_runsingle`).
//!
//! The variants hold what is valid in them: a connection lease exists from
//! the moment a transfer has a connection until `Done` gives it back, and
//! only `Done` gives it back.

use std::fmt;
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use curl_alloc::{OutOfMemory, TryArc, TryVec};

use crate::conn::chain::{Chain, Head, SetupPoint};
use crate::conn::io::{Closer, Events, Queued, Remote, ResolveFailure, SocketKey};
use crate::conn::layer::{LayerAnswer, LayerCx, LayerQuery};
use crate::conn::pool;
use crate::conn::proxy::{self, Refused};
use crate::conn::shutdown::ConnSettings;
use crate::conn::{
    Acquired, Answer, Asked, BadEntry, BadVia, Conn, ConnLease, ConnSlot, ConnectError,
    ConnectMachine, Connected, Dial, DriveOptions, Drove, Finish, Found, Full, Home, Limit,
    ListEntry, Made, NetRoute, Peer, Pool, PoolNote, PreProxy, Progress, ProxyCreds, ProxyRoute,
    Released, ReuseRules, Route, Unresolved, WaitReason, parse_entry, queries,
};
use crate::deliver::{Directions, Pause, PauseRequest, Pipeline, RecvPause};
use crate::easy::Easy;
use crate::error::{ErrorKind, UrlErrorKind, url_error};
use crate::options::{Flow, Method, Options, ProxyType, ResolveList};
use crate::progress::rate::{RateLimits, Verdict, Way};
use crate::progress::{self, Speedometer};
use crate::share::Kind;

mod h2tunnel;
mod h3tunnel;
use h3tunnel::Tunnels;
mod haproxy;
mod https;
mod names;
mod quictunnel;
pub(crate) mod side;
pub(crate) use side::{Shaken, SideSetup};
mod socks;
pub(crate) mod tls;
mod tunnel;
use crate::components::Component;
use crate::proto::http::negotiate::Wants as AuthWants;
use crate::proto::http1::follow;
use crate::proto::http1::follow::Inherited;
use crate::proto::{Before, Connect, DoPhase, DoStep, Ended, ProtoState, ProtoStep, Waiting};
use crate::report::{Ends, Marked, Starts, Timer, TransferReport};
use crate::text::Text;
use crate::time::{Instant, TimeLimit};
use crate::tls::{TlsIdentity, TlsNative, TlsWait};
use crate::trace::{self, Ip};
use crate::upload::{self, Readers};
use crate::url::{self, GetOptions, ParseOptions, Part, SetOptions, Url};
use crate::version::Protocol;

use super::cx::{DriveCx, EngineRest, EventCx, Kept, TransferCalls, TransferCx};
use super::mstate::{self, MState};
use super::sched::RowSet;
use super::sockets::{Pollset, Wants};
use super::timers::{Deadlines, Phase, TimeLeft, TimerKind, wait_ms};
use super::{Census, Host, Life, PushFields, PushOffer, Pushed, Rows, Slots, TransferId};
use tls::TlsSide;

/// The longest host name a URL may name (`MAX_URL_LEN`).
const MAX_HOST: usize = 0xffff;

/// What came of a push offered to the application.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Offered {
    /// Taken: this transfer has it.
    Added(TransferId),
    /// Refused (`CURL_PUSH_DENY`), or taken but not added.
    Denied,
    /// Refused, the parent to fail (`CURL_PUSH_ERROROUT`).
    Failed,
}

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
    /// Where the first request went (`state.initial_origin`): what the
    /// application said for it goes nowhere else.
    first: Option<Origin>,
    /// The method, which a redirect may have turned into a GET
    /// (`state.httpreq`).
    method: Method,
    /// What the requests followed so far change for the next.
    course: Course,
    /// What HTTP's next request takes from the ones before it, kept for
    /// HTTP and not read here.
    http: Inherited,
    /// It has run its first step, and is neither done nor gone
    /// (`state.really_alive`).
    pub(crate) alive: bool,
    /// Its URL is a pattern, as its options said as its last request
    /// started (`state.wildcardmatch`).
    wildcard_match: bool,
    /// The wildcard download, from its first request on: kept here
    /// between its requests, and lent to each (`data->wildcard`).
    wildcard: Option<Box<crate::proto::ftp::Wildcard>>,
}

impl Run {
    /// Take the transfer out of the multi before it completed
    /// (`TransferState::abandon`).
    pub(crate) fn abandon<H: Host>(self, cx: &mut StepCx<'_, H>) {
        let Run {
            state, mut http, ..
        } = self;
        state.abandon(cx, &mut http);
    }

    pub(crate) fn new() -> Run {
        Run {
            state: TransferState::Init,
            deadlines: Deadlines::new(None, None),
            url: Vec::new(),
            retries: 0,
            first: None,
            method: Method::Get,
            course: Course::START,
            http: Inherited::new(crate::options::HttpVersion::Any),
            alive: false,
            wildcard_match: false,
            wildcard: None,
        }
    }
}

/// The request is about to be made: the application hears of the
/// connection first, and may stop the request (`multistate_do`'s
/// `fprereq`, as DO starts); one only connecting too.
fn enter_do<H: Host>(x: Attached, cx: &mut StepCx<'_, H>) -> (TransferState, Wake) {
    match prereq(cx) {
        Ok(()) => (TransferState::Do(x), Wake::Again),
        Err(kind) => (
            TransferState::Done(x.done(Err(kind), false, Reached::Unmade)),
            Wake::Again,
        ),
    }
}

/// The request is made: about to send, or sent already with no body
/// (`mstate_enter_did`).
fn enter_did<H: Host>(x: Attached, cx: &mut StepCx<'_, H>) -> (TransferState, Wake) {
    mstate::enter(cx, MState::Did);
    cx.mark(Timer::PreTransfer);
    let send = x.proto.wants_send(cx.easy().options());
    if !send {
        cx.mark(Timer::PostTransfer);
    }
    (TransferState::Did(x), Wake::Again)
}

/// The application's pre-request handler told of the connection a
/// request is about to be made over: an abort fails the transfer
/// (`multistate_do`'s `fprereq`).
fn prereq<H: Host>(cx: &mut StepCx<'_, H>) -> Result<(), ErrorKind> {
    let options = cx.easy().options();
    let Some(handler) = options.sockets.prereq.clone() else {
        return Ok(());
    };
    let ends = cx.easy().report().primary().cloned();
    match handler.prereq(&mut TransferCx::new(cx), ends.as_ref()) {
        Ok(()) => Ok(()),
        Err(super::Abort) => {
            let why = format_args!("operation aborted by pre-request callback");
            Err(trace::fail(cx, ErrorKind::AbortedByCallback, why))
        }
    }
}

/// What the requests followed so far change for the next.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Course {
    /// `Options::port` no longer applies: a redirect led to an absolute
    /// URL (`state.allow_port` cleared).
    port_dropped: bool,
    /// A `Location:` was followed, so each request from here on is
    /// limited to the redirect protocols (`state.this_is_a_follow`).
    followed: bool,
}

impl Course {
    const START: Course = Course {
        port_dropped: false,
        followed: false,
    };

    fn allows_port(self) -> bool {
        !self.port_dropped
    }

    fn drop_port(&mut self) {
        self.port_dropped = true;
    }

    fn followed(self) -> bool {
        self.followed
    }

    fn follow(&mut self) {
        self.followed = true;
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
    /// The transfer is over without a request made: the wildcard
    /// download it is had no more to get. Its end is no DONE
    /// (`multistate_do`'s skip to COMPLETED).
    Nothing,
    /// The same URL is asked for again on a fresh connection, the reused
    /// one having died (C's `FOLLOW_RETRY`).
    Retry,
    /// The response's `Location:`, as the server gave it, is followed
    /// (C's `FOLLOW_REDIR`); `code` is the response's. A `reload` asks
    /// for the same URL again, to answer a challenge or drop `Expect:`:
    /// counted as a redirect, as C counts it, but no redirect for what
    /// the next request may reach (`this_is_a_follow`).
    Follow {
        location: Vec<u8>,
        code: u16,
        reload: bool,
    },
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
    /// Holding a connection, the protocol to connect over it (C's
    /// PROTOCONNECT).
    ProtoConnect(Attached),
    /// The protocol's connect under way, waiting for what it waits for
    /// (PROTOCONNECTING).
    ProtoConnecting(Attached),
    /// Making its request (DO).
    Do(Attached),
    /// The first half of its request under way, waiting (DOING).
    Doing(Attached),
    /// The second half of its request under way, waiting (DOING_MORE).
    DoingMore(Attached),
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
    route: NetRoute,
    /// How the first attempt dials it, which its setup takes over.
    dial: Dial,
}

/// A request whose connection is being set up.
#[derive(Debug)]
pub(crate) struct Connecting {
    lease: ConnLease,
    proto: ProtoState,
    /// The plan's route: the host and port the request is for, the peer
    /// connected to in their place and the proxy on the way, as the
    /// failure names them.
    route: NetRoute,
    /// The HTTPS connect filter heading the setup, if it has one.
    https: Option<https::HttpsConnect>,
    /// The race of an HTTP/3 attempt against one over TCP, once its first
    /// started: what the second is made from, and the QUIC attempt out
    /// of the lease while both run.
    race: Option<Box<Race>>,
    /// HTTP Negotiate with the proxy a tunnel goes through, before the
    /// connection it belongs to is up: kept across a redial, as C keeps it
    /// on the connection whose filters it makes again, and handed to the
    /// connection as it comes up.
    negotiate: Option<Box<crate::proto::http::negotiate::Negotiate>>,
}

/// A machine and its handshake apart, for as long as a handshake's driver
/// works on the two together: the handshake goes back to the machine as
/// this goes.
struct SetupMut<'a> {
    machine: &'a mut ConnectMachine,
    handshake: Option<Box<Handshake>>,
}

impl<'a> SetupMut<'a> {
    fn of(machine: &'a mut ConnectMachine) -> Self {
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
struct Lent<'a> {
    route: &'a NetRoute,
    request: &'a mut dyn SetupLend,
    negotiate: &'a mut Option<Box<crate::proto::http::negotiate::Negotiate>>,
    rank: ConnRank,
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
enum Failure {
    Attempt(ErrorKind),
    Transfer(ErrorKind),
}

impl Failure {
    /// A handshake's failure with `kind`: its attempt's, as C's HTTPS
    /// connect filter takes a baller's result, but running out of memory,
    /// which fails the transfer.
    fn of(kind: ErrorKind) -> Failure {
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
struct Race {
    /// The addresses the first resolved, which the second races.
    answer: TryArc<Answer>,
    /// The connection's makings, which the second is made with.
    makings: (Closer, ConnSettings, Instant),
    /// The second attempt.
    second: RaceSecond,
    /// Which attempt leads: a second over TCP once it starts, else the
    /// first.
    lead: Attempt,
    /// When the first started (`ctx->started`), which the second's
    /// timeouts count from.
    at: Instant,
    /// The first failed, with this (`ballers[0].result`), which is the
    /// setup's if the second fails too.
    first_failed: Option<ErrorKind>,
    /// The first attempt, if it failed once dialed: its connection kept
    /// until the race ends, as C keeps a failed baller's chain. The
    /// lease holds it failed, with no machine.
    failed: Option<ConnectMachine>,
    /// The first's peer answered, found once asked (`reply_ms`), which is
    /// not asked again.
    replied: bool,
}

/// Where a race's second attempt stands.
#[derive(Debug)]
enum RaceSecond {
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
    fn running(&self) -> Option<&ConnectMachine> {
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
    fn into_machine(self) -> Option<ConnectMachine> {
        match self {
            RaceSecond::Running(m) | RaceSecond::Kept(m) => Some(m),
            RaceSecond::Unstarted | RaceSecond::Gone => None,
        }
    }

    /// Its machine, if it failed once dialed.
    fn kept(&self) -> Option<&ConnectMachine> {
        match self {
            RaceSecond::Kept(m) => Some(m),
            RaceSecond::Unstarted | RaceSecond::Running(_) | RaceSecond::Gone => None,
        }
    }
}

/// One of a race's attempts: the first, the lease's, or the second.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Attempt {
    First,
    Second,
}

impl Attempt {
    /// The attempt beside it.
    fn other(self) -> Attempt {
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
    fn filter(&self) -> Component {
        match self {
            Handshake::Socks(_) => Component::Socks,
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
    fn interest(&self, setup: &ConnectMachine) -> Events {
        match self {
            Handshake::Socks(s) => setup.handshake_pollset(s.interest()),
            Handshake::Connect(t) => setup.handshake_pollset(t.interest()),
            Handshake::H2Connect(p) => setup.handshake_pollset(p.connect_interest()),
            Handshake::Quic(q) => setup.handshake_pollset(q.wants()),
            Handshake::Haproxy(p) => setup.handshake_pollset(p.interest()),
            Handshake::Tls(_) => setup.handshake_pollset(Events::NONE),
        }
    }
}

/// Who the request is for (C's `conn->origin`), shared with the
/// connection's route.
pub(crate) type Origin = TryArc<Peer>;

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
    /// Whether the chain of writers of a protocol dropped before it
    /// connected was made (C's `req.writer.stack`): HTTP's is, its header
    /// collector installed as the connection is set up. Read only without
    /// `proto`, whose pipeline says it otherwise (`chain_made`).
    unconnected_chain: bool,
    result: Result<(), ErrorKind>,
    /// Ended before the request was complete.
    premature: bool,
    reached: Reached,
    /// The host connected to, if any, as a connection kept names it.
    origin: Option<Origin>,
    next: AfterRequest,
    /// The race its setup ran, if it failed racing: its attempt out of
    /// the lease goes with the lease's.
    race: Option<Box<Race>>,
    /// How far its end is.
    ending: Ending,
}

/// How far a request's end (`multi_done`) is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Ending {
    /// Not begun.
    Ahead,
    /// Begun, its protocol's `done` awaiting the last answer, which C
    /// reads blocking (`imap_block_statemach`): the transfer waits in
    /// DONE for what the protocol waits for.
    Waiting,
    /// Begun, and the protocol's wait given up, the transfer failed or
    /// taken out of the multi meanwhile: its connection, left within an
    /// answer, closes.
    Cut,
}

impl Done {
    /// Whether the request's chain of writers was made, which its end is
    /// said of (`Curl_cw_out_done`).
    fn chain_made(&mut self) -> bool {
        match self.proto.as_mut() {
            Some(proto) => proto.pipeline_mut().is_some_and(|p| p.made()),
            None => self.unconnected_chain,
        }
    }

    /// The request's result once its protocol's DONE came to `done`: the
    /// request's own failure stands over DONE's (`multi_done`'s callers:
    /// `if(!result) result = rc`), and a request to be made again from
    /// PERFORMING lets DONE's go (`(void)multi_done`), as only one from DO
    /// was failing already.
    fn done_with(&self, done: Result<(), ErrorKind>) -> Result<(), ErrorKind> {
        if self.next == AfterRequest::Retry && self.result.is_ok() {
            return Ok(());
        }
        self.result.and(done)
    }

    /// The next request is to send the body again: a retry always rewinds
    /// it (`Curl_retry_request`), a request the response asks for as the
    /// protocol decided (`Curl_creader_will_rewind`).
    fn rewinding(&self) -> bool {
        self.next == AfterRequest::Retry
            || self.proto.as_ref().is_some_and(ProtoState::rewinds_upload)
    }
}

/// How far a request got.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Reached {
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

    /// The TLS library's objects of the origin's connection the transfer
    /// holds, while it holds one: through its request's end, its last
    /// progress pass among it, until `release` lets the connection go, as
    /// C's `multi_done` detaches it only then.
    /// A key's connection is reached through `pool`; without it, or
    /// while another transfer's step has it out, it has none.
    pub(crate) fn tls_native(&self, pool: Option<&Pool>) -> Option<TlsNative> {
        if let TransferState::Connecting(c) = self {
            return native_of(c.query(LayerQuery::TlsNative));
        }
        let lease = self.lease()?;
        let slot = match pool {
            Some(pool) => pool.slot_of(lease)?,
            // Without the pool, a key in its place cannot be reached.
            None => lease.holding()?,
        };
        native_of(slot.query(LayerQuery::TlsNative))
    }

    /// The connection the transfer holds, wherever it is, if it is not
    /// out with another transfer's step.
    fn slot<'a>(&'a self, pool: &'a Pool) -> Option<&'a ConnSlot> {
        pool.slot_of(self.lease()?)
    }

    /// What the origin's TLS session waits for on the socket, if it
    /// waits.
    fn tls_waits(&self, pool: &Pool) -> Option<TlsWait> {
        self.waits(LayerQuery::TlsWaits, pool)
    }

    /// What an HTTPS proxy's TLS session waits for on the socket, if it
    /// waits, and whether the tunnel through it is made, whose filter,
    /// connected, asks it again (`cf_h1_proxy_adjust_pollset`).
    fn proxy_tls_waits(&self, pool: &Pool) -> Option<(TlsWait, bool)> {
        let waits = self.waits(LayerQuery::ProxyTlsWaits, pool)?;
        let tunneled = match self {
            TransferState::Connecting(c) => {
                matches!(c.lead().map(ConnectMachine::reached), Some(SetupPoint::Dialed(m)) if m.tunnel.is_some())
            }
            state => state
                .slot(pool)
                .and_then(ConnSlot::open)
                .is_some_and(Conn::tunnels),
        };
        Some((waits, tunneled))
    }

    /// What the TLS session `q` asks of waits for, if it waits.
    fn waits(&self, q: LayerQuery, pool: &Pool) -> Option<TlsWait> {
        let answer = match self {
            TransferState::Done(_) => None,
            TransferState::Connecting(c) => c.query(q),
            state => state.slot(pool)?.query(q),
        };
        match answer? {
            LayerAnswer::TlsWaits(TlsWait::Nothing) => None,
            LayerAnswer::TlsWaits(waits) => Some(waits),
            LayerAnswer::TlsNative(_)
            | LayerAnswer::Alpn(..)
            | LayerAnswer::TlsDeferred
            | LayerAnswer::Tunnel(_)
            | LayerAnswer::Failure(_) => {
                unreachable!("an answer of another question")
            }
        }
    }

    /// The lease the transfer holds, if it holds one.
    fn lease_mut(&mut self) -> Option<&mut ConnLease> {
        match self {
            TransferState::Connecting(c) => Some(&mut c.lease),
            TransferState::Done(d) => Some(&mut d.lease),
            _ => self.attached_mut().map(|a| &mut a.lease),
        }
    }

    fn attached(&self) -> Option<&Attached> {
        match self {
            TransferState::ProtoConnect(x)
            | TransferState::ProtoConnecting(x)
            | TransferState::Do(x)
            | TransferState::Doing(x)
            | TransferState::DoingMore(x)
            | TransferState::Did(x)
            | TransferState::Exchanging(x)
            | TransferState::RateLimiting(x) => Some(x),
            _ => None,
        }
    }

    fn attached_mut(&mut self) -> Option<&mut Attached> {
        match self {
            TransferState::ProtoConnect(x)
            | TransferState::ProtoConnecting(x)
            | TransferState::Do(x)
            | TransferState::Doing(x)
            | TransferState::DoingMore(x)
            | TransferState::Did(x)
            | TransferState::Exchanging(x)
            | TransferState::RateLimiting(x) => Some(x),
            _ => None,
        }
    }

    /// Replay the output its request holds, unless a handler holds it
    /// still: HTTP's with a WebSocket's connection lent for its frames.
    pub(crate) fn flush_output<H: Host>(
        &mut self,
        cx: &mut StepCx<'_, H>,
    ) -> Result<(), ErrorKind> {
        match self.attached_mut() {
            Some(Attached {
                proto: ProtoState::Http(req),
                lease,
                ..
            }) => req.flush_output(cx, lease),
            Some(x) => match x.proto.pipeline_mut() {
                Some(p) => p.flush(cx),
                None => Ok(()),
            },
            None => Ok(()),
        }
    }

    /// Whether the request under way holds output for the application.
    #[cfg(debug_assertions)]
    pub(crate) fn holds_output(&self) -> bool {
        self.attached().is_some_and(|x| x.proto.holds_output())
    }

    /// Whether its request's end waits for its protocol's last answer.
    pub(crate) fn awaits_end(&self) -> bool {
        matches!(self, TransferState::Done(d) if d.ending == Ending::Waiting)
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

    /// When the protocol wants to look again whatever its socket says,
    /// and the timer that wakes it: HTTP's wait for a 100, or a line
    /// protocol's DONE as it awaits its answer, whose wake C has no timer
    /// for (it blocks), so it is the server's time to answer's.
    pub(crate) fn due(&self) -> Option<(TimerKind, Instant)> {
        match self {
            TransferState::ProtoConnecting(x)
            | TransferState::Doing(x)
            | TransferState::DoingMore(x)
            | TransferState::Did(x)
            | TransferState::Exchanging(x)
            | TransferState::RateLimiting(x) => x.proto.due().map(|at| (x.proto.due_timer(), at)),
            TransferState::Done(d) if d.ending == Ending::Waiting => d
                .proto
                .as_ref()
                .and_then(ProtoState::due)
                .map(|at| (TimerKind::ServerResponse, at)),
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
            TransferState::Connecting(mut c) => TransferState::Done(Done {
                unconnected_chain: c.proto.pipeline_mut().is_some_and(|p| p.made()),
                lease: c.lease,
                proto: None,
                result: Err(err),
                premature: true,
                reached: Reached::Unmade,
                origin: Some(c.route.origin),
                next: AfterRequest::Complete,
                race: c.race,
                ending: Ending::Ahead,
            }),
            TransferState::ProtoConnect(x)
            | TransferState::ProtoConnecting(x)
            | TransferState::Do(x) => TransferState::Done(x.done(Err(err), true, Reached::Unmade)),
            TransferState::Doing(x) | TransferState::DoingMore(x) => {
                TransferState::Done(x.done(Err(err), true, Reached::Making))
            }
            TransferState::Did(x)
            | TransferState::Exchanging(x)
            | TransferState::RateLimiting(x) => {
                TransferState::Done(x.done(Err(err), true, Reached::Made))
            }
            // Its protocol's wait is given up, the first failure kept.
            TransferState::Done(mut d) if d.ending == Ending::Waiting => {
                d.lease.get().mark_close();
                d.ending = Ending::Cut;
                if d.result.is_ok() {
                    d.result = Err(err);
                }
                TransferState::Done(d)
            }
            s @ (TransferState::Done(_) | TransferState::Completed(_)) => s,
        }
    }

    /// Where the transfer is in C's states, when the engine's say: a
    /// request ended otherwise than whole stays where it ended, as it is
    /// done with there.
    fn c_state(&self) -> Option<MState> {
        Some(match self {
            TransferState::Init => return None,
            TransferState::Pending(_) => MState::Pending,
            TransferState::Setup(_) => MState::Connect,
            TransferState::Connecting(_) => MState::Connecting,
            TransferState::ProtoConnect(_) => MState::ProtoConnect,
            TransferState::ProtoConnecting(_) => MState::ProtoConnecting,
            TransferState::Do(_) => MState::Do,
            TransferState::Doing(_) => MState::Doing,
            TransferState::DoingMore(_) => MState::DoingMore,
            TransferState::Did(_) => MState::Did,
            TransferState::Exchanging(_) => MState::Performing,
            TransferState::RateLimiting(_) => MState::RateLimiting,
            TransferState::Done(d)
                if d.result.is_ok() && matches!(d.next, AfterRequest::Complete) =>
            {
                MState::Done
            }
            TransferState::Done(_) | TransferState::Completed(_) => return None,
        })
    }

    /// Take the transfer out of the multi before it completed: its
    /// request ends as a premature one, as `curl_multi_remove_handle`
    /// ends it, its status the transfer's, which no failure has set.
    pub(crate) fn abandon<H: Host>(self, cx: &mut StepCx<'_, H>, http: &mut Inherited) {
        // Its connection's TLS objects are the handlers' to reach while it
        // goes, as C's transfer still holds its connection in `multi_done`.
        cx.lent = self.tls_native(Some(&cx.rest.caches.pool));
        let done = match self {
            TransferState::Init
            | TransferState::Pending(_)
            | TransferState::Setup(_)
            | TransferState::Completed(_) => return,
            TransferState::Connecting(mut c) => Done {
                unconnected_chain: c.proto.pipeline_mut().is_some_and(|p| p.made()),
                lease: c.lease,
                proto: None,
                result: Ok(()),
                premature: true,
                reached: Reached::Unmade,
                origin: Some(c.route.origin),
                next: AfterRequest::Complete,
                race: c.race,
                ending: Ending::Ahead,
            },
            TransferState::ProtoConnect(x)
            | TransferState::ProtoConnecting(x)
            | TransferState::Do(x) => x.done(Ok(()), true, Reached::Unmade),
            TransferState::Doing(x) | TransferState::DoingMore(x) => {
                x.done(Ok(()), true, Reached::Making)
            }
            // Past its request, the connection is in no known state
            // (`curl_multi_remove_handle`'s `streamclose`).
            TransferState::Did(x)
            | TransferState::Exchanging(x)
            | TransferState::RateLimiting(x) => x.done(Ok(()), true, Reached::Made),
            // Taken out as its protocol awaits its last answer: the wait
            // is given up, the end premature, so the connection closes.
            TransferState::Done(mut d) => {
                assert_eq!(
                    d.ending,
                    Ending::Waiting,
                    "a request's end is run by the step that reaches it"
                );
                d.premature = true;
                d.ending = Ending::Cut;
                d
            }
        };
        // A protocol whose end awaits its last answer even for a request
        // cut short (`smtp_done` after a mail's body, sent or not) has the
        // wait given up at once, as for one taken out as it waited.
        let ended = match multi_done(cx, http, done) {
            Err(mut waiting) => {
                waiting.premature = true;
                waiting.ending = Ending::Cut;
                multi_done(cx, http, waiting)
            }
            ended => ended,
        };
        // C drops what `multi_done` says as the handle leaves: an abort
        // the progress handler asks for has nothing left to stop.
        assert!(ended.is_ok(), "an end given up awaits nothing");
    }
}

/// What a request's end left: its protocol, how it ended and what comes
/// next.
struct RequestEnd {
    proto: Option<ProtoState>,
    result: Result<(), ErrorKind>,
    reached: Reached,
    next: AfterRequest,
}

/// The request is over, whole, failed or taken out of the multi
/// (`multi_done`): the protocol says its last, the progress its last,
/// the output and the request end, and the connection goes back. A
/// protocol that awaits its last answer leaves it waiting in DONE,
/// given back to be run again as what it waits for comes.
fn multi_done<H: Host>(
    cx: &mut StepCx<'_, H>,
    http: &mut Inherited,
    mut d: Done,
) -> Result<RequestEnd, Done> {
    // A key's connection is in its place outside a step, as a removed
    // transfer's is.
    cx.rest.caches.pool.check_out(&mut d.lease);
    // Whether the request was cut short is decided by how it ended, not
    // by the protocol's last word, which comes first.
    let mut premature = d.premature || is_premature(d.result);
    let exchanged = d.reached == Reached::Exchanged;
    match d.ending {
        Ending::Ahead => {
            // A failure other than its stream's closes an HTTP/2
            // connection, which outlives a request otherwise
            // (`multistate_performing`'s `streamclose`).
            if d.result.is_err_and(|e| e != ErrorKind::Http2Stream) && d.lease.multiplexes() {
                d.lease.get().mark_close();
            }
            mstate::trace(
                cx,
                format_args!(
                    "multi_done: status: {} prem: {} done: 0",
                    trace::Code(d.result),
                    u8::from(premature)
                ),
            );
            if let Some(proto) = d.proto.as_mut() {
                match proto.done(
                    cx,
                    &mut d.lease,
                    d.result,
                    premature,
                    &d.next,
                    http,
                    exchanged,
                ) {
                    // The transfer's own failure stands over DONE's
                    // (`multi_done`'s callers: `if(!result) result = rc`).
                    crate::proto::Finish::Done(result) => d.result = d.done_with(result),
                    crate::proto::Finish::Waiting => {
                        d.ending = Ending::Waiting;
                        return Err(d);
                    }
                }
            }
        }
        Ending::Waiting => {
            let proto = d.proto.as_mut().expect("only a protocol waits as it ends");
            match proto.finishing(cx, &mut d.lease, exchanged) {
                crate::proto::Finish::Done(result) => d.result = d.done_with(result),
                crate::proto::Finish::Waiting => return Err(d),
            }
        }
        Ending::Cut => {}
    }
    // A last progress pass, unless the transfer never connected (C's
    // `mstate > MSTATE_CONNECTING`) or a callback aborted already: a
    // failed connect draws no meter and calls no handler.
    if d.proto.is_some()
        && d.result != Err(ErrorKind::AbortedByCallback)
        && let Err(e) = progress::finish(cx, d.reached == Reached::Exchanged)
        && d.result.is_ok()
    {
        d.result = Err(e);
        premature |= is_premature(d.result);
    }
    if d.chain_made() {
        crate::deliver::Pipeline::done(cx);
    }
    let max_age = cx.easy().options().limits.reuse.dns_max_age;
    let now = cx.rest.now;
    let kept = cx.rest.kept(cx.me, Kind::Names);
    let (_, mut names) = cx.rest.net_names(cx.me, kept.as_ref());
    names.section(|dns| dns.prune(now, max_age));
    let stream_closed = d.premature && d.reached != Reached::Unmade;
    // The request is over (`Curl_req_done`), unless it failed.
    if d.result.is_ok() {
        upload::trace_reset(cx, d.rewinding());
    }
    if let Some(proto) = d.proto.as_mut() {
        proto.data_done(cx, &mut d.lease);
    }
    // A race given up closes its first attempt, then its second, as C's
    // connect filter destroys its ballers in their order
    // (`cf_hc_ctx_destroy`), each running or failed once dialed. They go
    // with the connection, on no transfer's trace, their sockets
    // announced gone.
    let raced = d.race.take().map(|race| {
        let Race { second, failed, .. } = *race;
        let me = cx.me;
        let mut close = |m: ConnectMachine| m.close(&mut cx.rest.announcing(me));
        for m in [
            failed.or_else(|| d.lease.fail_setup()),
            second.into_machine(),
        ]
        .into_iter()
        .flatten()
        {
            close(m);
        }
    });
    release(
        cx,
        d.lease,
        premature,
        stream_closed,
        d.origin.as_ref(),
        raced.is_some(),
    );
    Ok(RequestEnd {
        proto: d.proto,
        result: d.result,
        reached: d.reached,
        next: d.next,
    })
}

/// HTTP/3's session said how many transfers connection `number` takes,
/// with `in_use` on it (`cf_ngtcp2_query`).
fn trace_max_concurrent<H: Host>(
    cx: &mut StepCx<'_, H>,
    number: crate::conn::ConnNumber,
    max: u32,
    in_use: u32,
) {
    let n = number.get();
    trace::of(
        cx,
        Component::Http3,
        format_args!("query conn[{n}]: MAX_CONCURRENT -> {max} ({in_use} in use)"),
    );
}

/// The readers kept for the next request are rewound
/// (`Curl_client_start`).
fn client_start<H: Host>(cx: &mut StepCx<'_, H>) {
    trace::of(
        cx,
        Component::Read,
        format_args!("client start, rewind readers"),
    );
}

/// Give the transfer's connection back, and trace its fate
/// (`Curl_cpool_return`, `cpool_conn_close`).
///
/// `stream_closed` says the transfer marked the connection for closing
/// as it failed past its request (`streamclose`), which only the trace
/// tells: a premature end closes it anyway.
fn release<H: Host>(
    cx: &mut StepCx<'_, H>,
    lease: ConnLease,
    premature: bool,
    stream_closed: bool,
    origin: Option<&Origin>,
    raced: bool,
) {
    // The connection's objects go with its lease: the step lends them no
    // more (`Curl_detach_connection`).
    cx.lent = None;
    // A key given back outside its step, as an abandoned transfer's is,
    // has its connection out to say what became of it.
    let mut lease = lease;
    cx.rest.caches.pool.check_out(&mut lease);
    // How many transfers its session takes, as C asks a connection no
    // transfer is on any more that it would keep (`multi_done_locked`):
    // none once its server shut it down. Said only if it was asked.
    let asked = match lease.is_up() {
        true => lease.conn().session().map(|s| {
            use crate::conn::mux::Mux as _;
            let max = s.max_concurrent(0, cx.max_streams());
            (max, s.says_max_concurrent())
        }),
        false => None,
    };
    let finish = Finish {
        premature,
        forbid_reuse: cx.easy().options().limits.reuse.forbid,
        reserve: cx.easy().options().connect_only.reserves(),
        shut_down: asked.is_some_and(|(max, _)| max == 0),
    };
    let number = lease.is_up().then(|| lease.conn().number());
    let now = cx.rest.now;
    let limit = Limit {
        max: cx.rest.tell.limits.max_connects,
        attached: cx.rest.tell.slots.len(),
    };
    if lease.setup().and_then(ConnectMachine::answer).is_some() || raced {
        // A setup given up lets its answer go (`CF_CTRL_DATA_DONE`), a
        // race's once.
        let kept = cx.rest.kept(cx.me, Kind::Names);
        cx.rest.net_names(cx.me, kept.as_ref()).1.release();
    }
    let home = lease.home().clone();
    let closes = lease.closes() || stream_closed;
    let multiplex = u8::from(lease.multiplexes());
    let released = match home {
        // A share's lease, lent to the multi: the last key gives it back to
        // the share's pool. Each is a use of the share's pool, as C
        // returns any under its lock (`Curl_cpool_return`).
        Home::Share(ref share) => {
            let mut lease = lease;
            // What the share's upkeep asked of the connection, lent here,
            // is done before the return starts its interval again, under
            // the share's pool's own lock.
            let ask = share.pool().take_ask(lease.id());
            if let Some(ask) = ask
                && lease.is_up()
            {
                ask.keep_alive(lease.get(), now);
            }
            cx.rest.caches.pool.check_in(&mut lease);
            let back = cx.rest.caches.pool.release_lent(lease, now);
            cx.rest
                .pool_section(cx.me, &home, |pool, exits, here| match back {
                    pool::LentBack::InUse(n) => Released::InUse(n),
                    pool::LentBack::Last(lease) => {
                        pool.release(here, lease, finish, limit, exits, now)
                    }
                })
        }
        Home::Multi => cx.rest.pool_section(cx.me, &home, |pool, exits, here| {
            let mut lease = lease;
            pool.check_in(&mut lease);
            pool.release(here, lease, finish, limit, exits, now)
        }),
    };
    let in_use = match released {
        Released::InUse(n) => n.get(),
        _ => 0,
    };
    mstate::trace(cx, format_args!("multi_done_locked, in use={in_use}"));
    if in_use > 0 {
        mstate::trace(
            cx,
            format_args!("Connection still in use {in_use}, no more multi_done now!"),
        );
    }
    let kept_or_shut = matches!(
        released,
        Released::Idle { .. } | Released::Evicted(_) | Released::ShutDown { .. }
    );
    if kept_or_shut && let (Some((max, true)), Some(number)) = (asked, number) {
        trace_max_concurrent(cx, number, max, 0);
    }
    if let Released::ShutDown { number: n, .. } = released {
        let (host, port) = origin.map_or((&b""[..], 0), |o| (o.name(), o.port()));
        let conn = Text::<64>::clipped(format_args!("multi_done, conn {n} to ")).0;
        let rest =
            Text::<64>::clipped(format_args!(":{port} was shutdown by server, not reusing")).0;
        mstate::trace_with(cx, &[conn.bytes(), host, rest.bytes()]);
    }
    if let Released::Closed(n) | Released::Terminated(n) = &released {
        // A connection to no host, a file's, has an empty name.
        let (host, port) = origin.map_or((&b""[..], 0), |o| (o.name(), o.port()));
        let conn = Text::<64>::clipped(format_args!("multi_done, terminating conn {n} to ")).0;
        let rest = Text::<96>::clipped(format_args!(
            ":{port}, forbid={}, close={}, premature={}, conn_multiplex={multiplex}",
            u8::from(finish.forbid_reuse),
            u8::from(closes),
            u8::from(finish.premature)
        ))
        .0;
        mstate::trace_with(cx, &[conn.bytes(), host, rest.bytes()]);
    }
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
            let conn = Text::<64>::clipped(format_args!("Connection {n} to host ")).0;
            let rest = Text::<24>::clipped(format_args!(":{} left intact", origin.port())).0;
            trace::info_with(cx, &[conn.bytes(), origin.shown(), rest.bytes()]);
        }
        Released::Closed(n)
        | Released::ShutDown {
            number: n,
            premature: false,
        } => trace::info(cx, format_args!("shutting down connection {n}")),
        Released::Terminated(n)
        | Released::ShutDown {
            number: n,
            premature: true,
        } => trace::info(cx, format_args!("closing connection {n}")),
        Released::InUse(_) => {}
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
    /// leaves only the pause's, which the protocol applies. The
    /// connection's layers adjust what an exchange waits for, if it waits
    /// for anything (`Curl_conn_adjust_pollset`).
    pub(crate) fn pollset<'a>(
        &'a self,
        pause: Pause,
        pool: &'a Pool,
    ) -> Result<Pollset<'a>, OutOfMemory> {
        let mut set = Pollset::new();
        match self {
            TransferState::Connecting(c) if pause.recv == RecvPause::Running => {
                // The race's attempts in their order (`cf_hc_adjust_pollset`):
                // the one out of the lease first if it is the first.
                let leads = https::other_leads(c);
                let lead = c.leader();
                let order = match c.beside() {
                    Some(other) if leads => [Some(other), Some(lead)],
                    other => [Some(lead), other],
                };
                for a in order.into_iter().flatten() {
                    attempt_pollset(c, a, &mut set)?;
                }
            }
            TransferState::ProtoConnecting(x)
            | TransferState::Doing(x)
            | TransferState::DoingMore(x) => {
                let phase = match self {
                    TransferState::ProtoConnecting(_) => Waiting::Connecting,
                    TransferState::Doing(_) => Waiting::Doing,
                    _ => Waiting::More,
                };
                if let Some(slot) = pool.slot_of(&x.lease) {
                    let events = slot.adjust_pollset(x.proto.waits(phase, slot.line()), None);
                    for s in slot.sockets() {
                        set.add(s, events)?;
                    }
                    // A second connection, set up beside it, waits for
                    // what its setup does (`ftp_domore_pollset`).
                    for (s, events) in x.proto.side_pollset(Events::NONE) {
                        set.add(s, events)?;
                    }
                }
            }
            TransferState::Done(d) if d.ending == Ending::Waiting => {
                let proto = d.proto.as_ref().expect("only a protocol waits as it ends");
                if let Some(slot) = pool.slot_of(&d.lease) {
                    let events = slot.adjust_pollset(proto.waits(Waiting::Done, slot.line()), None);
                    for s in slot.sockets() {
                        set.add(s, events)?;
                    }
                }
            }
            TransferState::Exchanging(x) => {
                // A connection another transfer's step has out waits for
                // nothing of this one's until it is back.
                if let Some(slot) = pool.slot_of(&x.lease) {
                    let events = slot
                        .adjust_pollset(x.proto.interest(pause, slot.line()), x.proto.h3_sending());
                    for s in slot.sockets() {
                        set.add(s, events)?;
                    }
                    // The data a second connection moves (`Curl_xfer_setup_recv`
                    // of `SECONDARYSOCKET`).
                    for (s, events) in x.proto.side_pollset(x.proto.side_interest(pause)) {
                        set.add(s, events)?;
                    }
                }
            }
            _ => {}
        }
        Ok(set)
    }
}

/// What attempt `a` of a setup waits for. A handshake waits for what it
/// sends or reads, and to read too, as the socket's filter, connected but
/// not yet in use, adds (`cf_socket_adjust_pollset`); with none under
/// way, a TCP attempt waits to write, a QUIC one for what its connection
/// waits for.
fn attempt_pollset<'a>(
    c: &'a Connecting,
    a: Attempt,
    set: &mut Pollset<'a>,
) -> Result<(), OutOfMemory> {
    let Some(setup) = c.attempt(a) else {
        return Ok(());
    };
    match c.handshake(a) {
        Some(h) => {
            let events = h.interest(setup) | Events::IN;
            for s in setup.sockets() {
                set.add(s, events)?;
            }
        }
        None => {
            for (s, events) in setup.racing_wants() {
                set.add(s, events)?;
            }
        }
    }
    Ok(())
}

/// What a transfer's pollset trace says, read from its run before the
/// trace calls out, so the run stays in its slot meanwhile
/// (`Curl_multi_pollset`).
pub(crate) struct PollsetTrace<T> {
    wants: Wants,
    /// What the protocol's pollset says, if it says it, before the
    /// layers adjust it.
    proto: Option<Events>,
    /// While the setup runs, what its sockets' filters say.
    setup: Option<SetupTrace>,
    /// What the origin's TLS session waits for, if it waits.
    tls: Option<TlsWait>,
    /// What an HTTPS proxy's waits for, if it waits, and whether a tunnel
    /// through it is made.
    proxy_tls: Option<(TlsWait, bool)>,
    timers: T,
    /// Sending and receiving, paused.
    paused: (bool, bool),
}

/// What a setup's sockets' filters say of the pollset.
pub(crate) struct SetupTrace {
    /// The race's attempt beside the lead, QUIC's, connected as its
    /// sockets open: their number, and whether they come first, that
    /// attempt the first, or last.
    other: usize,
    other_leads: bool,
    /// Whether the leading setup's sockets are connected, a handshake
    /// under way over the one dialed.
    dialed: bool,
    /// What their filter traces as.
    component: Component,
    /// The leading setup's happy eyeballs filter is not connected yet:
    /// its attempts race.
    eyeballs: bool,
    /// An HTTPS connect filter heads the setup.
    https: bool,
}

impl Run {
    /// What the transfer's pollset trace says, its pause `pause`.
    pub(crate) fn pollset_trace(
        &self,
        pause: Pause,
        pool: &Pool,
    ) -> Result<PollsetTrace<impl Iterator<Item = (Instant, TimerKind)> + Clone + use<>>, OutOfMemory>
    {
        let wants = self.state.pollset(pause, pool)?.into_wants();
        let setup = match &self.state {
            // A QUIC socket is connected as its attempt starts.
            TransferState::Connecting(c) => Some(SetupTrace {
                other: c.other().map_or(0, |m| m.racing_wants().count()),
                other_leads: https::other_leads(c),
                dialed: matches!(
                    c.lead().map(ConnectMachine::reached),
                    Some(SetupPoint::Dialed(_))
                ) || c.lead().is_some_and(|m| m.dial() == Dial::Quic),
                component: c.socket_component(),
                eyeballs: matches!(
                    c.lead().map(ConnectMachine::reached),
                    Some(SetupPoint::Racing { started: true })
                ),
                https: c.https.is_some(),
            }),
            _ => None,
        };
        // A protocol's own pollset, which C asks for in these states only.
        let proto = match &self.state {
            TransferState::ProtoConnecting(x) | TransferState::Doing(x) => x
                .proto
                .pollset_said(false, pool.slot_of(&x.lease).and_then(ConnSlot::line)),
            TransferState::Exchanging(x) => x
                .proto
                .pollset_said(true, pool.slot_of(&x.lease).and_then(ConnSlot::line)),
            _ => None,
        };
        Ok(PollsetTrace {
            wants,
            proto,
            setup,
            tls: self.state.tls_waits(pool),
            proxy_tls: self.state.proxy_tls_waits(pool),
            timers: self.deadlines.in_order(),
            paused: (pause.send_paused(), pause.recv != RecvPause::Running),
        })
    }
}

impl PollsetTrace<std::iter::Empty<(Instant, TimerKind)>> {
    /// The pollset of a transfer that waits on nothing and has no timer,
    /// its pause `pause`: one taken out of the multi.
    pub(crate) fn gone(pause: Pause) -> Self {
        PollsetTrace {
            wants: Wants::NONE,
            proto: None,
            setup: None,
            tls: None,
            proxy_tls: None,
            timers: std::iter::empty(),
            paused: (pause.send_paused(), pause.recv != RecvPause::Running),
        }
    }
}

impl<T: Iterator<Item = (Instant, TimerKind)> + Clone> PollsetTrace<T> {
    /// Traced as C traces a pollset as it is made: the socket filter's
    /// part in it while the connection is set up, the set with the number
    /// of timers armed, then each timer in the order they fire.
    pub(crate) fn trace<H: Host>(self, cx: &mut StepCx<'_, H>) {
        // The protocol's part, said as it is made: SSH's, its poll flags
        // in hex (`Curl_ssh_pollset`).
        if let Some(events) = self.proto {
            let flags =
                u8::from(events.contains(Events::IN)) | u8::from(events.contains(Events::OUT)) << 1;
            trace::of(cx, Component::Ssh, format_args!("pollset, flags={flags:x}"));
        }
        let all = self.wants.as_slice();
        // The race's attempt out of the lease, in its turn.
        let (other, leads) = self
            .setup
            .as_ref()
            .map_or((0, true), |s| (s.other, s.other_leads));
        let (first, wants, last) = if leads {
            let (first, wants) = all.split_at(other);
            (first, wants, &[][..])
        } else {
            let (wants, last) = all.split_at(all.len() - other);
            (&[][..], wants, last)
        };
        // The happy eyeballs filter over a racing attempt says how many
        // sockets the pollset has so far (`cf_ip_happy_adjust_pollset`).
        let eyeballs = |cx: &mut StepCx<'_, H>, n: usize| {
            let line = format_args!("adjust_pollset -> 0, {n} socks");
            trace::of(cx, Component::HappyEyeballs, line);
        };
        // The QUIC attempt beside the lead, its eyeballs racing while its
        // handshake is made.
        let udp = |cx: &mut StepCx<'_, H>, sockets: &[(SocketKey, Events)], n: usize| {
            for &(key, _) in sockets {
                let fd = key.get();
                let line = format_args!("adjust_pollset, !active, POLLIN fd={fd}");
                trace::of(cx, Component::Udp, line);
            }
            if !sockets.is_empty() {
                eyeballs(cx, n);
            }
        };
        udp(cx, first, first.len());
        // The TLS filter puts its socket in for what its session waits
        // for (`Curl_ssl_adjust_pollset`).
        if let (Some(waits), Some(&(key, _))) = (self.tls, wants.first()) {
            let fd = key.get();
            let line = match waits {
                TlsWait::Send => format_args!("adjust_pollset, POLLOUT fd={fd}"),
                TlsWait::Recv | TlsWait::Nothing => format_args!("adjust_pollset, POLLIN fd={fd}"),
            };
            trace::of(cx, Component::Ssl, line);
        }
        // An HTTPS proxy's, below it, asked twice once a tunnel through it
        // is made: by the tunnel's filter and on its own.
        if let (Some((waits, tunneled)), Some(&(key, _))) = (self.proxy_tls, wants.first()) {
            let fd = key.get();
            for _ in 0..1 + u8::from(tunneled) {
                let line = match waits {
                    TlsWait::Send => format_args!("adjust_pollset, POLLOUT fd={fd}"),
                    TlsWait::Recv | TlsWait::Nothing => {
                        format_args!("adjust_pollset, POLLIN fd={fd}")
                    }
                };
                trace::of(cx, Component::SslProxy, line);
            }
        }
        if let Some(SetupTrace {
            dialed,
            component,
            eyeballs: racing,
            https,
            ..
        }) = self.setup
        {
            for &(key, _) in wants {
                let fd = key.get();
                if dialed {
                    let line = format_args!("adjust_pollset, !active, POLLIN fd={fd}");
                    trace::of(cx, component, line);
                } else {
                    let line = format_args!("adjust_pollset, !connected, POLLOUT fd={fd}");
                    trace::of(cx, component, line);
                }
            }
            if racing && !wants.is_empty() {
                eyeballs(cx, first.len() + wants.len());
            }
            udp(cx, last, all.len());
            // The HTTPS connect filter, not connected while the setup
            // runs, says how many sockets the pollset has below it
            // (`cf_hc_adjust_pollset`).
            if https {
                let n = all.len();
                let line = format_args!("adjust_pollset -> 0, {n} socks");
                trace::of(cx, Component::HttpsConnect, line);
            }
        }
        if !trace::traces(cx, Component::Multi) {
            return;
        }
        let n = self.timers.clone().count();
        let fd = |&(key, events): &(SocketKey, Events)| {
            let fd = key.get();
            let r#in = if events.contains(Events::IN) {
                "IN"
            } else {
                ""
            };
            let out = if events.contains(Events::OUT) {
                "OUT"
            } else {
                ""
            };
            FdEvents(fd, r#in, out)
        };
        match all {
            [] => {
                let (send, recv) = (u8::from(self.paused.0), u8::from(self.paused.1));
                mstate::trace(
                    cx,
                    format_args!("pollset[], timeouts={n}, paused {send}/{recv} (r/w)"),
                );
            }
            [one] => mstate::trace(cx, format_args!("pollset[{}], timeouts={n}", fd(one))),
            [one, two] => mstate::trace(
                cx,
                format_args!("pollset[{}, {}], timeouts={n}", fd(one), fd(two)),
            ),
            more => {
                let fds = more.len();
                mstate::trace(cx, format_args!("pollset[fds={fds}], timeouts={n}"));
            }
        }
        let now = cx.rest.clock.now();
        for (at, kind) in self.timers {
            let us = at.since(now).as_micros();
            trace_timer(cx, kind, format_args!("expires in {us}us"));
        }
    }
}

/// A socket in a pollset's trace: its descriptor and what it waits for.
struct FdEvents(i32, &'static str, &'static str);

impl fmt::Display for FdEvents {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "fd={} {}{}", self.0, self.1, self.2)
    }
}

impl Connecting {
    /// What the socket of the leading setup traces as: a race's second's
    /// is TCP's where the first dials QUIC. With the leading second gone,
    /// the first's, which runs on.
    fn socket_component(&self) -> Component {
        self.lead()
            .or(self.lease.setup())
            .map_or(Component::Tcp, |m| m.dialing().socket_component())
    }

    /// Whether a race's second leads.
    fn second_leads(&self) -> bool {
        self.leader() == Attempt::Second
    }

    /// The attempt that leads: the first, unless a race's second does.
    fn leader(&self) -> Attempt {
        self.race.as_ref().map_or(Attempt::First, |r| r.lead)
    }

    /// The attempt beside the lead, in a race.
    fn beside(&self) -> Option<Attempt> {
        self.race.as_ref().map(|r| r.lead.other())
    }

    /// Attempt `a`'s machine, while it runs: the lease's first, or a
    /// race's second.
    fn attempt(&self, a: Attempt) -> Option<&ConnectMachine> {
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
    fn handshake(&self, a: Attempt) -> Option<&Handshake> {
        self.attempt(a)?.handshake.as_deref()
    }

    /// The leading setup's machine, while it runs: the lease's, or a
    /// race's second's once it leads.
    fn lead(&self) -> Option<&ConnectMachine> {
        self.attempt(self.leader())
    }

    /// The leading setup's handshake under way, if one is.
    fn lead_handshake(&self) -> Option<&Handshake> {
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
    fn other(&self) -> Option<&ConnectMachine> {
        self.attempt(self.beside()?)
    }

    /// What the connection's layers answer `q`: the leading setup's, while
    /// it is set up.
    fn query(&self, q: LayerQuery) -> Option<LayerAnswer> {
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
    fn attached(self) -> TransferState {
        let Connecting {
            lease,
            proto,
            route,
            https: _,
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

impl Attached {
    fn done(self, result: Result<(), ErrorKind>, premature: bool, reached: Reached) -> Done {
        Done {
            lease: self.lease,
            proto: Some(self.proto),
            unconnected_chain: false,
            result,
            premature,
            reached,
            origin: self.origin,
            next: AfterRequest::Complete,
            race: None,
            ending: Ending::Ahead,
        }
    }

    /// The request is not made: the transfer is over.
    fn nothing(self) -> Done {
        Done {
            next: AfterRequest::Nothing,
            ..self.done(Ok(()), false, Reached::Unmade)
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

/// A layer working for the stepping transfer traces as it does, keeps
/// its failures and reports to it, and a QUIC connection receives in the
/// multi's room and sets the transfer's timer. No stream is the step's
/// own to hear of: a request's call on its connection hears them
/// (`H3Step`).
impl<H: Host> LayerCx for StepCx<'_, H> {
    fn now(&self) -> Instant {
        self.rest.now
    }

    fn trace(&mut self) -> Option<&mut dyn crate::conn::layer::Trace> {
        Some(self)
    }

    fn failures(&mut self) -> Option<&mut dyn crate::conn::layer::Failures> {
        Some(self)
    }

    fn transfer(&mut self) -> Option<&mut dyn crate::conn::layer::ForTransfer> {
        Some(self)
    }

    /// A multi always has one.
    fn tls_sessions(&mut self) -> Option<&mut dyn crate::conn::layer::TlsSessions> {
        Some(self)
    }

    fn early_data(&mut self) -> Option<&mut dyn crate::conn::layer::EarlyData> {
        Some(self)
    }

    fn quic_timer(&mut self) -> Option<&mut dyn crate::conn::layer::QuicTimer> {
        Some(self)
    }

    fn h3_streams(&mut self) -> Option<&mut dyn crate::conn::layer::H3Streams> {
        None
    }

    fn recv_room(&mut self) -> Option<&mut crate::conn::quic::RecvRoom> {
        Some(&mut *self.rest.sockbuf)
    }
}

impl<H: Host> crate::conn::layer::Trace for StepCx<'_, H> {
    fn line(&mut self, component: Component, line: std::fmt::Arguments<'_>) {
        trace::of(self, component, line);
    }

    fn line_with(&mut self, component: Component, parts: &[&[u8]]) {
        trace::of_with(self, component, parts);
    }

    fn info_line(&mut self, line: std::fmt::Arguments<'_>) {
        trace::info(self, line);
    }

    fn info_line_with(&mut self, parts: &[&[u8]]) {
        trace::info_with(self, parts);
    }

    fn says_info(&self) -> bool {
        self.easy().options().output.verbose
    }
}

impl<H: Host> crate::conn::layer::Failures for StepCx<'_, H> {
    fn keep(&mut self, kind: ErrorKind, why: std::fmt::Arguments<'_>) -> ErrorKind {
        trace::fail(self, kind, why)
    }

    fn keep_with(&mut self, kind: ErrorKind, parts: &[&[u8]]) -> ErrorKind {
        trace::fail_with(self, kind, parts)
    }

    fn keep_errno(&mut self, e: &std::io::Error) {
        self.report_mut().socket_failed(e);
    }
}

impl<H: Host> crate::conn::layer::ForTransfer for StepCx<'_, H> {
    fn debug_bytes(&mut self, kind: crate::handler::DebugKind, bytes: &[u8]) {
        trace::bytes(self, kind, bytes);
    }

    fn has_debug_handler(&self) -> bool {
        let options = self.easy().options();
        options.callbacks.debug.is_some() && options.output.verbose
    }

    fn certinfo_report(&mut self) -> Option<&mut TransferReport> {
        let asked = self.easy().options().tls.certinfo;
        asked.then(|| self.report_mut())
    }

    fn peer_verified(&mut self, filter: Component, result: i64) {
        if matches!(filter, Component::SslProxy | Component::H3Proxy) {
            self.report_mut().set_proxy_verify_result(result);
        } else {
            self.report_mut().set_verify_result(result);
        }
    }

    fn has_tls_handler(&self) -> bool {
        self.easy().options().tls.options.context.is_some()
    }

    /// The handler is given the context, which the transfer's handlers
    /// reach meanwhile as its connection's (`CURLINFO_TLS_SESSION`).
    fn hand_tls_context(&mut self, native: TlsNative) -> Result<(), ErrorKind> {
        let Some(handler) = self.easy().options().tls.options.context.clone() else {
            return Ok(());
        };
        let lent = self.lent.replace(native);
        let configured = handler.configure(&mut TransferCx::new(self), native);
        self.lent = lent;
        configured
    }

    fn stop_recv(&mut self) {
        let slot = self.rest.tell.slots.get_mut(self.me);
        slot.expect("the stepping transfer").pause.stop_recv();
    }

    fn seconds_since_1970(&self) -> i64 {
        self.rest.clock.unix_time()
    }
}

impl<H: Host> crate::conn::layer::EarlyData for StepCx<'_, H> {
    fn early_sent(&mut self, sent: i64) {
        self.report_mut().set_earlydata_sent(sent);
    }

    fn connected_late(&mut self) {
        let now = self.now();
        let marked = self.report_mut().timings_mut().mark(Timer::AppConnect, now);
        mstate::marked(self, Timer::AppConnect, marked);
    }
}

impl<H: Host> StepCx<'_, H> {
    /// The server has `left` to answer, in whole milliseconds, from now:
    /// the `SERVER_RESPONSE` timer is armed for it as the step ends, and
    /// said to be now (`Curl_expire`, as `Curl_pp_statemach` drives
    /// without blocking).
    pub(crate) fn server_response_in(&mut self, left: Duration) {
        let ms = left.as_millis();
        let at = self
            .now()
            .after(Duration::from_millis(u64::try_from(ms).unwrap_or(u64::MAX)));
        self.server_response_at = Some(at);
        if trace::traces(self, Component::Timer) {
            let us = ms.saturating_mul(1000);
            trace_timer(
                self,
                TimerKind::ServerResponse,
                format_args!("set for {us}us"),
            );
        }
    }
}

impl<H: Host> crate::conn::layer::QuicTimer for StepCx<'_, H> {
    fn due_in(&mut self, wait: Duration) {
        let at = self.rest.clock.now().after(wait);
        self.quic_at = Some(at);
        trace_set(self, TimerKind::Quic, at);
    }
}

impl<H: Host> crate::conn::layer::TlsSessions for StepCx<'_, H> {
    /// The share's if it keeps them (`cf_ssl_scache_get`), what it says
    /// held until its lock is let go, as nothing is called out from inside
    /// a share's lock; else the multi's, lent out of the multi for the
    /// call, so the context traces through while `f` holds it.
    fn with_cache(
        &mut self,
        f: &mut dyn FnMut(&mut crate::tls::SessionCache, &mut dyn crate::conn::layer::SessionSays),
    ) {
        use crate::share::watched;
        if let Some(kept) = self.rest.kept(self.me, Kind::SslSessions) {
            let mut held = HeldSays {
                traces: trace::traces(self, Component::Ssls),
                lines: Vec::new(),
                failure: None,
            };
            watched(kept.watch(), &kept.share, Kind::SslSessions, || {
                let mut sessions = kept.share.sessions();
                let cache = sessions.as_mut().expect("kept while the share keeps them");
                f(cache, &mut held);
            });
            for line in &held.lines {
                trace::of_with(self, Component::Ssls, &[line]);
            }
            if let Some((kind, why)) = held.failure {
                trace::fail_with(self, kind, &[&why]);
            }
            return;
        }
        let none = crate::tls::SessionCache::new(0);
        let mut own = std::mem::replace(&mut self.rest.caches.sessions, none);
        f(&mut own, self);
        self.rest.caches.sessions = own;
    }
}

/// The context of a use of a share's TLS sessions under its lock: what
/// the use traces and fails with is held, to be said once the lock is let
/// go. A line it has no memory to hold is not said.
pub(super) struct HeldSays {
    /// The transfer traces the cache's lines (`ssls`).
    pub(super) traces: bool,
    pub(super) lines: Vec<Vec<u8>>,
    pub(super) failure: Option<(ErrorKind, Vec<u8>)>,
}

impl crate::conn::layer::SessionSays for HeldSays {
    fn say_line(&mut self, component: Component, line: std::fmt::Arguments<'_>) {
        if self.traces
            && component == Component::Ssls
            && let Ok(line) = curl_alloc::try_format(line)
        {
            // Without memory to hold it, the line is not said, as a line
            // too long for the trace is cut.
            let _ = self.lines.try_push(line.into_bytes());
        }
    }

    fn say_failure(&mut self, kind: ErrorKind, why: std::fmt::Arguments<'_>) -> ErrorKind {
        if self.failure.is_none()
            && let Ok(why) = curl_alloc::try_format(why)
        {
            self.failure = Some((kind, why.into_bytes()));
        }
        kind
    }
}

/// What a step needs: the transfer it steps, whose `Run` is out of its
/// slot, and the rest of the multi.
pub(crate) struct StepCx<'a, H: Host> {
    pub(crate) me: TransferId,
    pub(super) rest: EngineRest<'a, H>,
    /// The TLS library's objects of the connection the transfer holds,
    /// lent for the step, whose run is out of reach of its handlers
    /// (`TransferCx::tls_native`).
    lent: Option<TlsNative>,
    /// When the QUIC library asked the step to call it again, the
    /// transfer's `QUIC` timer once the step is over.
    pub(crate) quic_at: Option<Instant>,
    /// When the server's time to answer runs out, as the step's line
    /// protocol last drove its back and forth: the transfer's
    /// `SERVER_RESPONSE` timer once the step is over.
    pub(crate) server_response_at: Option<Instant>,
    /// What a second connection's setup, as the step last moved it on,
    /// asks of the transfer's timers once the step is over.
    pub(crate) side_due: SideDue,
    /// The chain of the connection the step is working on, which its
    /// filters' lines name (`cf->sockindex`).
    rank: ConnRank,
    /// The connection a WebSocket's transfer holds, lent while its
    /// output is delivered and its upload read: its handlers send frames
    /// on it, and its frames' state is read and kept there. The one
    /// exception to decision 9 (ENGINE.md): what reaches it is only
    /// `TransferCx`'s WebSocket calls.
    ws: Option<crate::conn::WsLend<'a>>,
}

impl<H: Host> StepCx<'_, H> {
    /// The chain the lines said now belong to.
    pub(crate) fn rank(&self) -> ConnRank {
        self.rank
    }

    /// Run `f`, its work the connection's second chain's: its filters'
    /// lines name it, and no others do.
    pub(crate) fn as_second<R>(&mut self, f: impl FnOnce(&mut Self) -> R) -> R {
        let was = std::mem::replace(&mut self.rank, ConnRank::Second);
        let r = f(self);
        self.rank = was;
        r
    }
}

impl<'a, H: Host> StepCx<'a, H> {
    /// The connection's TLS objects as the step changed them, lent for
    /// the rest of it.
    pub(super) fn lend(&mut self, native: Option<TlsNative>) {
        self.lent = native;
    }

    pub(crate) fn new(me: TransferId, rest: EngineRest<'a, H>) -> StepCx<'a, H> {
        StepCx {
            me,
            rest,
            lent: None,
            quic_at: None,
            server_response_at: None,
            side_due: SideDue::default(),
            rank: ConnRank::First,
            ws: None,
        }
    }
}

impl<H: Host> StepCx<'_, H> {
    /// Run `f` with transfer `id`'s step context and its HTTP request, its
    /// run out of its slot meanwhile, as the stepping transfer hands it
    /// what the connection they share did for it (ENGINE.md 4.4); the
    /// connection's TLS objects, the same, are lent to it, and it is
    /// marked dirty, to run when its turn next comes, as C marks it
    /// (`Curl_multi_mark_dirty`). None if it is gone or makes no HTTP
    /// request.
    pub(crate) fn with_sibling<R>(
        &mut self,
        id: TransferId,
        f: impl FnOnce(&mut StepCx<'_, H>, &mut crate::proto::http::Request) -> R,
    ) -> Option<R> {
        let slot = self.rest.tell.slots.get_mut(id)?;
        // Only the stepping transfer's run is out while a connection is
        // read or written.
        let mut run = slot.run.take().expect("a sibling's run is in its slot");
        let lent = self.lent;
        let r = match run.state.attached_mut().map(|x| &mut x.proto) {
            Some(ProtoState::Http(req)) => {
                let mut cx = StepCx::new(id, self.rest.reborrow());
                cx.lent = lent;
                Some(f(&mut cx, req))
            }
            _ => None,
        };
        super::put_back(self.rest.tell.slots, self.rest.dirty, id, run);
        self.rest.dirty.insert(id.index());
        r
    }

    /// Run `f` with a WebSocket's connection lent to the step, for its
    /// handlers to send frames on and its output to be decoded with.
    pub(crate) fn lending_ws<R>(
        &mut self,
        conn: crate::conn::WsLend<'_>,
        f: impl FnOnce(&mut StepCx<'_, H>) -> R,
    ) -> R {
        assert!(self.ws.is_none(), "one connection lent at a time");
        let mut cx = StepCx {
            me: self.me,
            rest: self.rest.reborrow(),
            lent: self.lent,
            quic_at: self.quic_at,
            server_response_at: self.server_response_at,
            side_due: self.side_due,
            rank: self.rank,
            ws: Some(conn),
        };
        let r = f(&mut cx);
        let (quic_at, server_response_at) = (cx.quic_at, cx.server_response_at);
        self.quic_at = quic_at;
        self.server_response_at = server_response_at;
        self.side_due = cx.side_due;
        r
    }

    /// The WebSocket of the connection lent to the step, if one is.
    pub(crate) fn lent_ws(&mut self) -> Option<&mut crate::proto::ws::WsConn> {
        self.ws.as_mut().map(|l| l.parts().0)
    }

    /// Run `f` with the WebSocket's connection lent to the step, taken
    /// out of it meanwhile, so that `f` has the step too; none if no
    /// connection is lent.
    pub(crate) fn with_ws_conn<R>(
        &mut self,
        f: impl FnOnce(&mut StepCx<'_, H>, &mut crate::conn::WsLend<'_>) -> R,
    ) -> Option<R> {
        let mut conn = self.ws.take()?;
        let r = f(self, &mut conn);
        self.ws = Some(conn);
        Some(r)
    }

    /// Whether the application takes the responses servers push
    /// (`push_cb`).
    pub(crate) fn wants_push(&self) -> bool {
        self.rest.events.wants_push()
    }

    /// Offer the application a response the server promised beside the
    /// stepping transfer's request (`push_promise`): `easy`, made for it,
    /// its URL set. Taken, it is a transfer of the multi's from now, its
    /// run begun by `start` in its own context, as
    /// `Curl_multi_add_perform` takes it to PERFORMING at once.
    pub(crate) fn offer_push(
        &mut self,
        fields: &PushFields,
        easy: Box<Easy>,
        start: impl FnOnce(&mut StepCx<'_, H>, &mut Run) -> Result<(), ErrorKind>,
    ) -> Offered {
        // A multi a callback stopped takes nothing more.
        if *self.rest.tell.life == Life::Dead {
            return Offered::Denied;
        }
        let offer = PushOffer {
            parent: self.me,
            fields,
        };
        let t = &mut self.rest.tell;
        let mut ecx = EventCx {
            alive: &*t.alive,
            slots: &mut *t.slots,
            limits: &mut *t.limits,
            notify: &mut *t.notify,
            counts: t.counts.get(),
            sockets: &mut *t.sockets,
            // The pool is the step's, apart from the multi meanwhile.
            pool: None,
        };
        let (easy, owner) = match self.rest.events.push(&mut ecx, &offer, easy) {
            Pushed::Accepted { easy, owner } => (easy, owner),
            Pushed::Denied => return Offered::Denied,
            Pushed::Failed => return Offered::Failed,
        };
        let rest = &mut self.rest;
        let rows = Rows {
            slots: &mut *rest.tell.slots,
            timers: &mut *rest.timers,
            dirty: &mut *rest.dirty,
            notify: &mut *rest.tell.notify,
        };
        let inserted = super::insert(
            rows,
            &mut *rest.tell.counts,
            &mut rest.caches.pool,
            easy,
            owner,
        );
        let id = match inserted {
            Ok(id) => id,
            Err((refused, owner)) => {
                rest.events.unpushed(refused.easy, owner);
                return Offered::Denied;
            }
        };
        rest.dirty.insert(id.index());
        let slot = rest.tell.slots.get(id).expect("just added");
        rest.events.added(id, &slot.owner);
        let slot = rest.tell.slots.get_mut(id).expect("just added");
        let mut run = slot.run.take().expect("a new run in its slot");
        let lent = self.lent;
        let mut cx = StepCx::new(id, self.rest.reborrow());
        // On the stepping transfer's connection.
        cx.lent = lent;
        super::trace_membership(&mut cx, "added to");
        let started = start(&mut cx, &mut run);
        // One that could not begin fails as it next runs, and its stream
        // is refused.
        if let Err(kind) = started {
            fail_pushed(&mut run, kind);
        }
        super::put_back(self.rest.tell.slots, self.rest.dirty, id, run);
        match started {
            Ok(()) => Offered::Added(id),
            Err(_) => Offered::Denied,
        }
    }

    /// A key to the connection the stepping transfer's `lease` has out,
    /// for a transfer the server pushes on it. A share's not lent to the
    /// multi yet is lent now, as the step would lend it once done: the
    /// pushed transfer is the multi's, and joins it as C attaches it
    /// (`attached_multi`), unlocked as C sets the connection's field.
    pub(crate) fn pushed_lease(&mut self, lease: &mut ConnLease) -> Result<ConnLease, OutOfMemory> {
        let pool = &mut self.rest.caches.pool;
        if let Home::Share(share) = lease.home()
            && !pool.is_attached(lease)
        {
            let share = share.clone();
            pool.borrow(lease)?;
            share.pool().lend(lease.id());
        }
        Ok(pool.pushed(lease))
    }

    /// Step transfer `id` again in the pass: something it waits on, a
    /// connection it shares, changed.
    pub(crate) fn wake(&mut self, id: TransferId) {
        if self.rest.tell.slots.get(id).is_some() {
            self.rest.dirty.insert(id.index());
        }
    }

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

    /// The streams the multi lets a server open at once on an HTTP/2
    /// connection (`Curl_multi_max_concurrent_streams`).
    pub(crate) fn max_streams(&self) -> u32 {
        self.rest.tell.limits.max_streams.get()
    }

    pub(crate) fn pause(&self) -> Pause {
        self.rest
            .tell
            .slots
            .get(self.me)
            .expect("the stepping transfer")
            .pause
    }

    /// The readers C would stack for the request's body.
    pub(crate) fn readers_mut(&mut self) -> &mut Option<Readers> {
        &mut self
            .rest
            .tell
            .slots
            .get_mut(self.me)
            .expect("the stepping transfer")
            .readers
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

    /// What is left of the transfer's time, as of the step's start: its
    /// connect limit counts before DO (`Curl_timeleft_ms`).
    pub(crate) fn time_left(&self) -> TimeLeft {
        let limits = self.easy().options().limits;
        let phase = if self.mstate() < MState::Do {
            Phase::Connecting
        } else {
            Phase::Transferring
        };
        Deadlines::new(limits.total, limits.connect).time_left(starts(self), self.now(), phase)
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
    fn rate_parts(&mut self) -> (&mut RateLimits, &Flow, Pause, Instant) {
        let now = self.rest.now;
        let slot = self
            .rest
            .tell
            .slots
            .get_mut(self.me)
            .expect("the stepping transfer");
        (&mut slot.rate, &slot.easy.options().flow, slot.pause, now)
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
        let marked = self.report_mut().timings_mut().mark(timer, now);
        mstate::marked(self, timer, marked);
    }

    /// As `mark`, at the clock's time now rather than the pass's: C reads
    /// the clock for each mark (`Curl_pgrs_now`), and the queue time is
    /// what passed between two marks of one step.
    pub(crate) fn mark_now(&mut self, timer: Timer) {
        let now = self.rest.clock.now();
        let marked = self.report_mut().timings_mut().mark(timer, now);
        mstate::marked(self, timer, marked);
    }

    /// Where the transfer is in C's states.
    pub(crate) fn mstate(&self) -> MState {
        self.rest
            .tell
            .slots
            .get(self.me)
            .expect("the stepping transfer")
            .mstate
    }

    pub(super) fn set_mstate(&mut self, state: MState) {
        let slot = self.rest.tell.slots.get_mut(self.me);
        slot.expect("the stepping transfer").mstate = state;
    }
}

impl<H: Host> TransferCalls for StepCx<'_, H> {
    fn me(&self) -> TransferId {
        self.me
    }

    fn census(&self) -> Census {
        let tell = &self.rest.tell;
        super::census_of(tell.slots, tell.counts.get())
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

    fn ws_send(
        &mut self,
        bytes: &[u8],
        asked: &crate::ws::Asked<'_>,
    ) -> Result<crate::ws::Sent, ErrorKind> {
        crate::proto::http::ws::lent_send(self, bytes, asked)
    }

    fn ws_start_frame(&mut self, asked: &crate::ws::Asked<'_>) -> Result<(), ErrorKind> {
        crate::proto::http::ws::lent_start_frame(self, asked)
    }

    fn ws_recv(&mut self, buf: &mut [u8]) -> Result<crate::ws::Received, ErrorKind> {
        crate::proto::http::ws::lent_recv(self, buf)
    }

    fn ws_meta(&self) -> Option<crate::ws::Meta> {
        if self.easy().options().ws.raw {
            return None;
        }
        Some(self.ws.as_ref()?.ws().meta())
    }

    fn tls_native(&self, id: TransferId) -> Option<TlsNative> {
        if id == self.me {
            return self.lent;
        }
        let slot = self.rest.tell.slots.get(id)?;
        slot.run
            .as_ref()?
            .state
            .tls_native(Some(&self.rest.caches.pool))
    }
}

/// The TLS library's objects of the origin's connection, as its layers
/// answered `LayerQuery::TlsNative`.
pub(crate) fn native_of(answer: Option<LayerAnswer>) -> Option<TlsNative> {
    match answer? {
        LayerAnswer::TlsNative(native) => Some(native),
        LayerAnswer::Alpn(..)
        | LayerAnswer::TlsWaits(_)
        | LayerAnswer::TlsDeferred
        | LayerAnswer::Tunnel(_)
        | LayerAnswer::Failure(_) => {
            unreachable!("an answer of another question")
        }
    }
}

/// Ask a connection, from its filter `top`, what was agreed by ALPN
/// (`Curl_conn_cf_get_alpn_negotiated`), its layers having answered
/// `LayerQuery::Alpn` with `answer`: the filter says it is asked, and the
/// TLS session, if one answers, what it answers; the others answer none,
/// or pass the question on, saying nothing.
pub(crate) fn query_alpn<H: Host>(
    cx: &mut StepCx<'_, H>,
    answer: Option<LayerAnswer>,
    top: Component,
) -> Option<crate::tls::Chosen> {
    trace::of(cx, top, format_args!("query ALPN"));
    // An HTTPS proxy's TLS answers only when asked first: a tunnel's
    // filter above it keeps the question (`cf_h1_proxy_query`).
    if let Some(LayerAnswer::Alpn(chosen, filter)) = answer
        && (filter != Component::SslProxy || top == Component::SslProxy)
    {
        // QUIC's filter answers saying nothing (`cf_ngtcp2_query`).
        if filter != Component::Http3 {
            let name = chosen.map_or("(nil)", crate::tls::Chosen::name);
            let line = format_args!("query ALPN: returning '{name}'");
            trace::of(cx, filter, line);
        }
        return chosen;
    }
    None
}

/// Replay a transfer's held output, from outside its step.
pub(crate) fn flush<H: Host>(run: &mut Run, cx: &mut StepCx<'_, H>) -> Result<(), ErrorKind> {
    cx.lent = run.state.tls_native(Some(&cx.rest.caches.pool));
    let flushed = run.state.flush_output(cx);
    cx.lent = None;
    flushed
}

/// When the running transfer and its request started.
fn starts<H: Host>(cx: &StepCx<'_, H>) -> Starts {
    cx.easy()
        .report()
        .timings()
        .starts()
        .expect("a running transfer has started")
}

/// Run one step of `run`, the connection it holds out of its place for
/// the step if it multiplexes, and its TLS objects lent to its handlers
/// meanwhile. A connection found to speak HTTP/2 in the step, the
/// multi's own and let multiplex, becomes one that does (ENGINE.md 4.4).
pub(crate) fn step<H: Host>(run: &mut Run, cx: &mut StepCx<'_, H>) -> Wake {
    if let Some(lease) = run.state.lease_mut() {
        cx.rest.caches.pool.check_out(lease);
    }
    cx.lent = run.state.tls_native(Some(&cx.rest.caches.pool));
    let wake = step_lent(run, cx);
    cx.lent = None;
    // A connection of the multi's own found to speak HTTP/2 goes to its
    // place, for others to join as the search lets them
    // (`conn->bits.multiplex`).
    if let Some(x) = run.state.attached_mut() {
        let lease = &mut x.lease;
        if matches!(lease.home(), Home::Multi)
            && !cx.rest.caches.pool.is_attached(lease)
            && lease.multiplexes()
        {
            cx.rest.caches.pool.attach(lease);
            // One waiting to multiplex may join it now
            // (`Curl_conn_set_multiplex`).
            schedule_pending(&mut cx.rest);
            return wake;
        }
        // A share's is lent to the multi, whose transfers alone join it
        // while it does (`attached_multi`): its place in the share's pool
        // says so, unlocked as C sets the connection's field.
        if let Home::Share(share) = lease.home()
            && !cx.rest.caches.pool.is_attached(lease)
            && lease.multiplexes()
        {
            let share = share.clone();
            // Out of room to lend it, it serves its transfer alone.
            if cx.rest.caches.pool.borrow(lease).is_ok() {
                share.pool().lend(lease.id());
                schedule_pending(&mut cx.rest);
                return wake;
            }
        }
    }
    let settled = run.state.attached().is_some_and(|x| x.proto.settled_conn());
    if let Some(lease) = run.state.lease_mut() {
        let pool = &mut cx.rest.caches.pool;
        let attached = pool.is_attached(lease);
        pool.check_in(lease);
        // A share's says what it is in the share's pool, unlocked as C
        // reads `bits.multiplex`; a key, lent or the multi's, says nothing.
        let single = match lease.home() {
            _ if attached => false,
            Home::Multi => pool.settle(&Home::Multi, lease, settled),
            home @ Home::Share(share) => share.pool().settle(home, lease, settled),
        };
        if single {
            // One waiting for it to multiplex makes its own now.
            schedule_pending(&mut cx.rest);
        }
    }
    wake
}

fn step_lent<H: Host>(run: &mut Run, cx: &mut StepCx<'_, H>) -> Wake {
    let state = std::mem::replace(&mut run.state, TransferState::Init);
    // A piece of DO is within C's one call: no pass of its loop ends.
    let mut within_do = false;
    let (next, wake) = match state {
        TransferState::Init => {
            // Alive from its first step (`multistate_init`); a socket
            // callback's abort ends the step there.
            if !run.alive {
                run.alive = true;
                if cx.rest.tell.came_alive(&mut *cx.rest.events).is_err() {
                    return Wake::Idle;
                }
            }
            let limits = cx.easy().options().limits;
            run.deadlines = Deadlines::new(limits.total, limits.connect);
            let now = cx.rest.now;
            cx.report_mut().restart(now);
            *cx.speedometer_mut() = Speedometer::default();
            let next = match pretransfer(run, cx) {
                Ok(url) => {
                    mstate::enter(cx, MState::Setup);
                    cx.mark(Timer::StartOp);
                    start_leg(run, cx, url, false)
                }
                Err(kind) => TransferState::Init.fail(kind),
            };
            if next.is_completed() {
                complete(cx, now, true);
            }
            (next, Wake::Again)
        }
        TransferState::Pending(plan) => pending(run, plan, cx),
        TransferState::Setup(mut plan) => {
            // Let out of PENDING by another transfer (`multi_schedule_pending`).
            mstate::enter(cx, MState::Connect);
            // The request starts over (`Curl_req_hard_reset`).
            upload::trace_reset(cx, false);
            // The rest of the plan is kept, but C makes its connection
            // anew as a waiting transfer looks again, reading the IP
            // version then (`allocate_conn`, `url_match_conn`).
            plan.route.ip = cx.easy().options().ip_version;
            let now = cx.rest.now;
            let next = match run.deadlines.time_left(starts(cx), now, Phase::Connecting) {
                TimeLeft::Expired(_) => {
                    let kind = timed_out(cx, Phase::Connecting, true);
                    // Its failure may make room for another
                    // (`multi_runsingle`).
                    schedule_pending(&mut cx.rest);
                    TransferState::Init.fail(kind)
                }
                TimeLeft::Remaining(_) | TimeLeft::Unlimited => setup(cx, plan),
            };
            if next.is_completed() {
                complete(cx, now, true);
            }
            (next, Wake::Again)
        }
        TransferState::Connecting(c) => connecting(run, c, cx),
        // A reused connection's protocol connected as it was made
        // (`multistate_protoconnect`, `bits.reuse`).
        TransferState::ProtoConnect(x) if x.lease.conn().reused() => enter_do(x, cx),
        TransferState::ProtoConnect(mut x) => {
            match x
                .proto
                .connect(cx, &mut x.lease)
                .map_err(|e| layer_failed(&x.lease, e))
            {
                Ok(Connect::Done) => enter_do(x, cx),
                Ok(Connect::Waiting) => (TransferState::ProtoConnecting(x), Wake::Again),
                // Cut short (`multistate_protoconnect`).
                Err(e) => (
                    TransferState::Done(x.done(Err(e), true, Reached::Unmade)),
                    Wake::Again,
                ),
            }
        }
        // Out of time as the step starts, its connect not done: over, the
        // time counted from the leg's start (`multi_handle_timeout`,
        // `Curl_is_connecting`).
        TransferState::ProtoConnecting(x)
            if matches!(
                run.deadlines
                    .time_left(starts(cx), cx.rest.now, Phase::Connecting),
                TimeLeft::Expired(_)
            ) =>
        {
            let kind = timed_out(cx, Phase::Connecting, x.proto.sizes_request());
            (TransferState::ProtoConnecting(x).fail(kind), Wake::Again)
        }
        TransferState::ProtoConnecting(mut x) => {
            match x
                .proto
                .connect(cx, &mut x.lease)
                .map_err(|e| layer_failed(&x.lease, e))
            {
                Ok(Connect::Done) => enter_do(x, cx),
                Ok(Connect::Waiting) => {
                    buffered_input(&mut x, Some(Waiting::Connecting), cx);
                    (TransferState::ProtoConnecting(x), Wake::Idle)
                }
                // Cut short (`multistate_protoconnecting`).
                Err(e) => (
                    TransferState::Done(x.done(Err(e), true, Reached::Unmade)),
                    Wake::Again,
                ),
            }
        }
        // One that only connects is done once it has (`multistate_do`).
        TransferState::Do(x) if !cx.easy().options().connect_only.requests() => (
            TransferState::Done(x.done(Ok(()), false, Reached::Unmade)),
            Wake::Again,
        ),
        TransferState::Do(mut x) => match x
            .proto
            .make(cx, &mut x.lease, DoPhase::Do)
            .map_err(|e| layer_failed(&x.lease, e))
        {
            Ok(DoStep::Piece) => {
                within_do = true;
                (TransferState::Do(x), Wake::Again)
            }
            Ok(DoStep::Did) => enter_did(x, cx),
            Ok(DoStep::Nothing) => (TransferState::Done(x.nothing()), Wake::Again),
            // On to its rest, in the same pass (`multistate_do`).
            Ok(DoStep::Doing) => (TransferState::Doing(x), Wake::Again),
            Ok(DoStep::More) => (TransferState::DoingMore(x), Wake::Again),
            // A reused connection that died may be the request's
            // trouble: it is made again on a fresh one (`multistate_do`).
            Err(ErrorKind::SendError) if x.lease.conn().reused() => {
                let next = match retry_request(run, &mut x, cx, false) {
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
        // Out of time as the step starts (`multi_handle_timeout`), unless
        // the protocol times its DOING itself, as C's TELNET does in DO.
        TransferState::Doing(x) | TransferState::DoingMore(x)
            if !x.proto.times_itself() && expired(run, cx) =>
        {
            let kind = timed_out(cx, Phase::Transferring, x.proto.sizes_request());
            // Either half ends the same: past DO, cut short.
            (TransferState::Doing(x).fail(kind), Wake::Again)
        }
        TransferState::Doing(mut x) => match x
            .proto
            .make(cx, &mut x.lease, DoPhase::Doing)
            .map_err(|e| layer_failed(&x.lease, e))
        {
            Ok(DoStep::Did) => enter_did(x, cx),
            Ok(DoStep::Doing) => {
                buffered_input(&mut x, Some(Waiting::Doing), cx);
                (TransferState::Doing(x), Wake::Idle)
            }
            Ok(DoStep::More) => (TransferState::DoingMore(x), Wake::Again),
            Ok(DoStep::Piece | DoStep::Nothing) => unreachable!("only DO's step answers it"),
            // A failed request is done with, not cut short
            // (`multistate_doing`).
            Err(e) => (
                TransferState::Done(x.done(Err(e), false, Reached::Making)),
                Wake::Again,
            ),
        },
        TransferState::DoingMore(mut x) => match x
            .proto
            .make(cx, &mut x.lease, DoPhase::More)
            .map_err(|e| layer_failed(&x.lease, e))
        {
            Ok(DoStep::Did) => enter_did(x, cx),
            // Back to the first half (DOMORE_GOBACK).
            Ok(DoStep::Doing) => (TransferState::Doing(x), Wake::Again),
            Ok(DoStep::More) => {
                buffered_input(&mut x, Some(Waiting::More), cx);
                (TransferState::DoingMore(x), Wake::Idle)
            }
            Ok(DoStep::Piece | DoStep::Nothing) => unreachable!("only DO's step answers it"),
            // A failed request is done with, not cut short
            // (`multistate_doing_more`).
            Err(e) => (
                TransferState::Done(x.done(Err(e), false, Reached::Making)),
                Wake::Again,
            ),
        },
        // Without anything to exchange, the request is over
        // (`multistate_did`).
        // Out of time as the step starts, the request made: over
        // (`multi_handle_timeout`, ahead of the state's work).
        TransferState::Did(x) if expired(run, cx) => {
            let kind = timed_out(cx, Phase::Transferring, x.proto.sizes_request());
            (TransferState::Did(x).fail(kind), Wake::Again)
        }
        // Output the application paused is still held, and delivered in
        // PERFORMING: C goes to DONE and drops it, the transfer reported
        // a success (an open question, MILESTONES step 70).
        TransferState::Did(x) if !x.proto.exchanges() && !x.proto.holds_output() => (
            TransferState::Done(x.done(Ok(()), false, Reached::Made)),
            Wake::Again,
        ),
        TransferState::Did(x) => (TransferState::Exchanging(x), Wake::Again),
        // Out of time as the pass starts: nothing more is read or sent
        // (`multi_handle_timeout`, ahead of the state's work).
        TransferState::Exchanging(x) if expired(run, cx) => {
            let kind = timed_out(cx, Phase::Transferring, true);
            (TransferState::Exchanging(x).fail(kind), Wake::Again)
        }
        // Over a speed limit: nothing moves until it says
        // (`multistate_performing`'s first `mspeed_check`).
        TransferState::Exchanging(x) if over_limit(run, cx) => {
            (TransferState::RateLimiting(x), Wake::Idle)
        }
        TransferState::RateLimiting(x) => {
            if expired(run, cx) {
                let kind = timed_out(cx, Phase::Transferring, true);
                (TransferState::RateLimiting(x).fail(kind), Wake::Again)
            } else {
                // The progress and the low-speed check, then the limits
                // again (`multistate_ratelimiting`).
                match progress::check(cx, false) {
                    Err(e) => (TransferState::RateLimiting(x).fail(e), Wake::Again),
                    Ok(look_again) => {
                        if let Some(wait) = look_again {
                            arm(&mut run.deadlines, cx, TimerKind::SpeedCheck, wait);
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
            let stepped = x
                .proto
                .step(cx, &mut x.lease)
                .map_err(|e| layer_failed(&x.lease, e));
            if let Err(e) = stepped {
                sendrecv_failed(cx, e);
            }
            match stepped {
                // Received nothing, perhaps over a reused connection that
                // closed as it was reused (`multistate_performing`).
                Err(ErrorKind::RecvError) => match retry_request(run, &mut x, cx, false) {
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
                // A stream that said HTTP/1.1 is required is made again
                // in it, on a fresh connection, its failure let go
                // (`multistate_performing`).
                Err(ErrorKind::Http2Stream) if x.proto.h1_required() => {
                    trace::info(cx, format_args!("Downgrades to HTTP/1.1"));
                    x.proto.downgrade();
                    x.lease.get().mark_close();
                    trace::reset_fail(cx);
                    (
                        TransferState::Done(x.retried(Ok(()), Reached::Made)),
                        Wake::Again,
                    )
                }
                Err(e) => (TransferState::Exchanging(x).fail(e), Wake::Again),
                // `Curl_sendrecv` looks at the time limit again, but the
                // step's time is the one checked as it started.
                Ok(stepped) => {
                    // The end of a receive pass (`Curl_sendrecv`). A request
                    // is not over while output waits for the application to
                    // unpause (`multi.c`: `req.done` and the writers not
                    // paused).
                    let ended = stepped == ProtoStep::Done;
                    let done = ended && !x.proto.holds_output();
                    match progress::check(cx, done) {
                        Err(e) => {
                            sendrecv_failed(cx, e);
                            (TransferState::Exchanging(x).fail(e), Wake::Again)
                        }
                        Ok(look_again) => {
                            if let Some(wait) = look_again {
                                arm(&mut run.deadlines, cx, TimerKind::SpeedCheck, wait);
                            }
                            let retry = if ended {
                                retry_request(run, &mut x, cx, true)
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
                                // Decided as the exchange ends, before the
                                // progress pass below, so that the report
                                // is current when the application's
                                // progress callback reads it.
                                match exchanged(run, &mut x, cx) {
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
                                    buffered_input(&mut x, None, cx);
                                    (TransferState::Exchanging(x), Wake::Idle)
                                }
                            }
                        }
                    }
                }
            }
        }
        TransferState::Done(d) => 'done: {
            let mut d = match multi_done(cx, &mut run.http, d) {
                Ok(ended) => ended,
                // Its protocol awaits its last answer.
                Err(waiting) => break 'done (TransferState::Done(waiting), Wake::Idle),
            };
            // A wildcard download's request gives it back.
            let wildcard = d.proto.as_mut().and_then(ProtoState::take_wildcard);
            let more = wildcard.as_ref().is_some_and(|w| !w.done());
            if wildcard.is_some() {
                run.wildcard = wildcard;
            }
            // Held output went with the request; a pause the application
            // asked for stays.
            let pause = cx.pause_mut();
            if pause.recv == RecvPause::Held {
                pause.recv = RecvPause::Running;
                // Unpaused, the limit starts over (`Curl_req_reset`).
                cx.rate_start(Way::Recv, None);
            }
            let now = cx.rest.now;
            let leg = match (&d.next, d.result, d.proto.as_mut()) {
                // A send failure is what a retry from DO set out to mend.
                (AfterRequest::Retry, Ok(()) | Err(ErrorKind::SendError), Some(proto)) => {
                    Some(retry_leg(run, cx, proto))
                }
                (
                    AfterRequest::Follow {
                        location,
                        code,
                        reload,
                    },
                    Ok(()),
                    Some(proto),
                ) => {
                    if !reload {
                        run.course.follow();
                    }
                    Some(follow_leg(run, cx, proto, location, *code))
                }
                _ => None,
            };
            if let Some(next) = leg {
                if next.is_completed() {
                    complete(cx, now, true);
                }
                (next, Wake::Again)
            } else if more && d.result.is_ok() {
                // The download has more to get: its next request starts
                // from INIT (`multistate_done`).
                mstate::enter(cx, MState::Init);
                (TransferState::Init, Wake::Again)
            } else {
                complete(
                    cx,
                    now,
                    matches!(d.reached, Reached::Unmade | Reached::Making),
                );
                let completed = TransferState::Completed(Completed {
                    outcome: d.result,
                    message: Message::Unread,
                });
                (completed, Wake::Again)
            }
        }
        s @ TransferState::Completed(_) => (s, Wake::Idle),
    };
    let (next, wake) = if within_do {
        (next, wake)
    } else {
        // C's switch changes the state before its loop's progress pass
        // (`is_finished`), so the change is traced ahead of the meter.
        if let Some(state) = next.c_state() {
            mstate::enter(cx, state);
        }
        progress_after_step(next, wake, cx)
    };
    if next.is_completed() {
        // Its message is ready at once (`handle_completed`).
        if cx.mstate() != MState::MsgSent {
            mstate::enter(cx, MState::Completed);
            timers_cleared(run, cx);
            mstate::enter(cx, MState::MsgSent);
        }
        // Done: no longer alive (`multi_done`'s MSGSENT).
        if std::mem::replace(&mut run.alive, false) {
            cx.rest.tell.went(&mut *cx.rest.events);
        }
    } else if let Some(state) = next.c_state() {
        mstate::enter(cx, state);
    }
    run.state = next;
    wake
}

/// The transfer is complete: every timer it still has armed is cleared,
/// and said to be if there was one (`Curl_expire_clear_all` as it enters
/// COMPLETED). The protocol's own wait is derived from a state that no
/// longer waits, so it is not one: C clears it as the wait ends.
fn timers_cleared<H: Host>(run: &mut Run, cx: &mut StepCx<'_, H>) {
    run.deadlines.clear(TimerKind::Proto);
    run.deadlines.clear(TimerKind::FtpAccept);
    if run.deadlines.any() {
        run.deadlines.clear_all();
        mstate::trace(cx, format_args!("[TIMEOUT] all cleared"));
    }
}

/// A pass over the transfer's connection failed with `kind`
/// (`Curl_sendrecv`'s `DEBUGF`).
/// What a send or receive that failed with `e` failed with: a layer's
/// own error, where it named one, as a handshake put off for early data
/// fails with the handshake's (`ssl_cf_send`, `ssl_cf_recv`).
fn layer_failed(lease: &ConnLease, e: ErrorKind) -> ErrorKind {
    match (e, lease.query(LayerQuery::Failure)) {
        (ErrorKind::SendError | ErrorKind::RecvError, Some(LayerAnswer::Failure(kind))) => kind,
        _ => e,
    }
}

fn sendrecv_failed<H: Host>(cx: &mut StepCx<'_, H>, kind: ErrorKind) {
    let code = kind.number();
    trace::debug_info(cx, format_args!("Curl_sendrecv() -> {code}"));
}

/// Whether the transfer's time is up, as of the step's start.
fn expired<H: Host>(run: &Run, cx: &StepCx<'_, H>) -> bool {
    matches!(
        run.deadlines
            .time_left(starts(cx), cx.rest.now, Phase::Transferring),
        TimeLeft::Expired(_)
    )
}

/// A transfer that is to wait for input, as its protocol says for its
/// exchange or for the `phase` it waits in, while its connection holds
/// some where a poll cannot see it runs again in the next pass, as C's
/// pollset finds, says and marks it (`multi_adjust_pollset`): in
/// PERFORMING, and in PROTOCONNECTING, DOING and DOING_MORE, which wait
/// on the protocol's own pollset before the layers adjust it, unless its
/// receiving is over its limit. A step that stopped reading short has
/// marked it already (`ProtoStep::AtReadLimit`); one whose read found
/// nothing can still leave input held, taken in by its sends, as a QUIC
/// connection's are with its packets.
fn buffered_input<H: Host>(x: &mut Attached, phase: Option<Waiting>, cx: &mut StepCx<'_, H>) {
    let wants = match phase {
        Some(phase) => x.proto.waits(phase, x.lease.conn().line()),
        None => x.proto.interest(StepCx::pause(cx), x.lease.conn().line()),
    };
    let wants = wants.contains(Events::IN) && !matches!(cx.rate_allowance(Way::Recv), Some(..=0));
    if wants && x.lease.get().data_pending() {
        mstate::trace(
            cx,
            format_args!(
                "pollset[] has POLLIN, but there is still buffered input -> mark as dirty"
            ),
        );
        cx.rest.dirty.insert(cx.me.index());
    }
}

/// Whether the speed limits make the transfer wait now, its timer armed
/// for the wait and its run in the next pass called off; if not, the
/// timer is armed for when a limit next earns tokens, as the transfer
/// may need them to go on (`mspeed_check`, `EXPIRE_TOOFAST`). C's state
/// changes here, before the timer is armed, and each is traced.
fn over_limit<H: Host>(run: &mut Run, cx: &mut StepCx<'_, H>) -> bool {
    match cx.rate_verdict() {
        Verdict::Wait(wait) => {
            mstate::enter(cx, MState::RateLimiting);
            arm(&mut run.deadlines, cx, TimerKind::TooFast, wait);
            cx.rest.dirty.remove(cx.me.index());
            let ms = wait.as_millis();
            mstate::trace(cx, format_args!("[RLIMIT] waiting {ms}ms"));
            true
        }
        Verdict::Go(next) => {
            if let Some(next) = next {
                arm(&mut run.deadlines, cx, TimerKind::TooFast, next);
                let ms = next.as_millis();
                mstate::trace(cx, format_args!("[RLIMIT] next token update in {ms}ms"));
            }
            if cx.mstate() != MState::Performing {
                mstate::trace(cx, format_args!("[RLIMIT] wait over, continue"));
                mstate::enter(cx, MState::Performing);
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
        | TransferState::ProtoConnecting(_)
        | TransferState::Do(_)
        | TransferState::Doing(_)
        | TransferState::DoingMore(_)
        | TransferState::Did(_)
        | TransferState::Exchanging(_)
        | TransferState::RateLimiting(_)) => {
            let passed = progress::update(cx, false).and_then(|()| s.flush_output(cx));
            match passed {
                Ok(()) => (s, wake),
                Err(e) => (s.fail(e), Wake::Again),
            }
        }
        // Once begun, the end runs on as C's within `multi_done`, with no
        // pass of its loop's.
        TransferState::Done(d)
            if d.result.is_ok() && d.ending == Ending::Ahead && d.next != AfterRequest::Nothing =>
        {
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
            timed_out(cx, Phase::Connecting, true);
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
                | Handshake::Haproxy(_)
                | Handshake::Tls(_)
                | Handshake::Quic(_),
            )
            | None => {
                // Named for the name, while it is not resolved yet.
                let what = match c.lead().map(ConnectMachine::reached) {
                    Some(SetupPoint::Resolving) => "Resolving",
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
fn connect_ended_at<H: Host>(
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

/// `enter_setup` of the chain `setup` makes over `plan`, under `head`,
/// with the handshake `under_way` started.
fn enter_chain<H: Host>(
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
    let entry = |cx: &mut StepCx<'_, H>, chain: Chain| {
        mstate::trace(cx, format_args!("cf_setup_connect {chain}"));
    };
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
            if leg.version.resolves_locally() {
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
    let kept = cx.rest.kept(cx.me, Kind::Names);
    let answered = c.attempt(a).and_then(ConnectMachine::answer).is_some();
    let mut displaced = None;
    // An HTTP/3 proxy's tunnels are the race's attempts, checked first.
    let mut connected = match tunnels_drive(&mut c, cx, a) {
        Ok(Tunnels::Idle) => c.connect_attempt(
            a,
            &mut DriveCx {
                step: cx,
                kept: kept.as_ref(),
                deadlines: Some(&mut run.deadlines),
            },
            setup,
            &mut displaced,
            ConnectMachine::drive,
        ),
        decided => tunnel_decided(&mut c, a, run, cx, kept.as_ref(), &mut displaced, decided),
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
            decided => tunnel_decided(&mut c, a, run, cx, kept.as_ref(), &mut displaced, decided),
        };
    }
    if answered && c.attempt(a).and_then(ConnectMachine::answer).is_none() && c.race.is_none() {
        // Connected, or failed: the answer is let go; a race's, as the
        // race ends.
        cx.rest.net_names(cx.me, kept.as_ref()).1.release();
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
            run.deadlines.clear(TimerKind::AsyncName);
            // A Unix socket's address is made, not looked up
            // (`resolv_unix`).
            if !c.route.destination().is_unix() {
                trace_lookup(cx, &c.route, Some(found));
                if let Found::Stale(asked) | Found::Resolved(asked) = found {
                    let answer = c.attempt(a).and_then(|m| m.answer().cloned());
                    let addrs = answer.as_ref().map_or(&[][..], |a| a.addrs());
                    trace_resolved(cx, &c.route, Ok(asked), addrs);
                }
            }
            cx.mark(Timer::NameLookup);
            report_answer(cx, &c);
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
        Ok(Connected::Connecting(Progress::Resolving { retry })) => {
            match retry {
                Some(at) => name_retry(run, cx, at),
                None => run.deadlines.clear(TimerKind::AsyncName),
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
    kept: Option<&Kept>,
    displaced: &mut Option<ConnectMachine>,
    decided: Result<Tunnels, OutOfMemory>,
) -> Result<Connected, ConnectError> {
    let setup = drive_options(cx);
    let mut dcx = DriveCx {
        step: cx,
        kept,
        deadlines: Some(&mut run.deadlines),
    };
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
fn attempt_failed<H: Host>(
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
            _ => lost.discard(&mut DriveCx {
                step: cx,
                kept: None,
                deadlines: None,
            }),
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
        c.lead().and_then(|m| m.answer().cloned()),
        c.lead().map(ConnectMachine::makings),
    ) else {
        unreachable!("an attempt starts once its name is resolved");
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
            mstate::trace(cx, format_args!("cf_setup_connect {chain}"));
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
enum Due {
    Socks(crate::conn::socks::Version),
    Tunnel,
    Preface,
    Tls(TlsSide),
    /// The origin's QUIC connection, through a CONNECT-UDP tunnel.
    Quic,
}

/// The handshake to make next over `setup`, over `route`, which made
/// `made`, in cf-setup.c's order; none once they are all made.
fn handshake_due(route: &NetRoute, setup: &ConnectMachine, made: Made) -> Option<Due> {
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
fn start_handshake<H: Host>(
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
fn step_handshake<H: Host>(
    s: &mut SetupMut<'_>,
    t: &mut Lent<'_>,
    cx: &mut StepCx<'_, H>,
) -> Result<Wake, Failure> {
    let under_way = match s.handshake.as_deref().expect("a handshake under way") {
        Handshake::Socks(_) => socks::step,
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
    let queries = queries(peer, route.ip, cx.rest.ipv6_works).as_bytes();
    // The C debug build's line, said here always: only a debug build
    // fails the resolve.
    trace::of_with(
        cx,
        Component::Dns,
        &[b"[", queries, b"] hostip_resolv(", host, at.bytes(), b")"],
    );
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

/// The name `route` connects to first was looked up in the cache, as
/// C's `hostip_resolv` and `Curl_dnscache_get` trace it: found, missing
/// (or stale, said first) and so resolved, or `None`, the resolver's no
/// kept from before.
fn trace_lookup<H: Host>(cx: &mut StepCx<'_, H>, route: &NetRoute, found: Option<Found>) {
    // The name looked up: the proxy's, or what a connect-to names in the
    // origin's place.
    let peer = route.destination();
    let (name, at, queries) = (
        peer.name(),
        port_text(peer.port()),
        queries(peer, route.ip, cx.rest.ipv6_works),
    );
    let at = at.bytes();
    // The C debug build's line.
    #[cfg(feature = "debug-hooks")]
    trace::of_with(
        cx,
        Component::Dns,
        &[
            b"[",
            queries.as_bytes(),
            b"] hostip_resolv(",
            name,
            at,
            b")",
        ],
    );
    match found {
        Some(Found::Stale(_)) => {
            trace::info(cx, format_args!("Hostname in DNS cache was stale, zapped"));
        }
        // What the resolver said no to is kept as an entry without
        // addresses (`fetch_entry`).
        None => trace::of(
            cx,
            Component::Dns,
            format_args!("cache entry does not have type={queries} addresses"),
        ),
        Some(_) => {}
    }
    let (code, not) = match found {
        Some(Found::Cached) => (Ok(()), ""),
        Some(Found::Stale(_) | Found::Resolved(_)) => (Ok(()), "not "),
        None => (Err(ErrorKind::CouldntResolveHost), "not "),
    };
    let code = trace::Code(code);
    let rest = Text::<64>::clipped(format_args!(" queries={queries} -> {code} {not}found")).0;
    trace::of_with(
        cx,
        Component::Dns,
        &[b"cache lookup ", name, at, rest.bytes()],
    );
    if let Some(
        Found::Stale(Asked::Resolver(Some(q))) | Found::Resolved(Asked::Resolver(Some(q))),
    ) = found
    {
        let xfer = cx.easy().report().transfer_number().map_or(0, |n| n.get());
        let dns = Component::Dns;
        crate::conn::say_queued(xfer, q, name, at, &mut |parts| {
            trace::of_with(cx, dns, parts);
        });
    }
    if found == Some(Found::Cached) {
        trace::info_with(cx, &[b"Hostname ", name, b" was found in DNS cache"]);
    }
}

/// A second connection's `setup` moves on by one event, as the
/// transfer's own does: through the names the transfer keeps, its
/// share's if it shares them. The answer its name resolved to, let go as
/// it connects or fails, is told to the share (`Curl_dns_entry_unlink`).
pub(crate) fn side_drive<H: Host>(
    cx: &mut StepCx<'_, H>,
    setup: ConnectMachine,
) -> Result<Drove, ConnectError> {
    let options = drive_options(cx);
    let kept = cx.rest.kept(cx.me, Kind::Names);
    let answered = setup.answer().is_some();
    let drove = setup.drive(
        &mut DriveCx {
            step: cx,
            kept: kept.as_ref(),
            deadlines: None,
        },
        options,
    );
    let holds = matches!(&drove, Ok(Drove::Connecting(m, _)) if m.answer().is_some());
    if answered && !holds {
        cx.rest.net_names(cx.me, kept.as_ref()).1.release();
    }
    drove
}

/// A second connection's setup, dialed, let go of the answer its name
/// resolved to, made or given up: told to the share as `side_drive`
/// tells it.
pub(crate) fn side_let_go<H: Host>(cx: &mut StepCx<'_, H>) {
    let kept = cx.rest.kept(cx.me, Kind::Names);
    cx.rest.net_names(cx.me, kept.as_ref()).1.release();
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
    eyeballs: SideTimer,
    name: SideTimer,
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
        Progress::Resolving { retry } => {
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
        let addrs = setup.answer().map_or(&[][..], |a| a.addrs());
        trace_resolved(cx, route, Ok(asked), addrs);
    }
}

/// The name `route` connects to first was resolved, `asked` what
/// answered, to `addrs`, its answer kept; or the resolver failed, having
/// queued what the error says. A shortcut answers at once; the resolver,
/// as the reference build's c-ares does, answers later (`CURLE_AGAIN`),
/// its polls not traced.
fn trace_resolved<H: Host>(
    cx: &mut StepCx<'_, H>,
    route: &NetRoute,
    asked: Result<Asked, Option<Queued>>,
    addrs: &[IpAddr],
) {
    let peer = route.destination();
    let (name, at, queries) = (
        peer.name(),
        port_text(peer.port()),
        queries(peer, route.ip, cx.rest.ipv6_works),
    );
    let at = at.bytes();
    let code = match asked {
        Ok(Asked::Shortcut) => 0,
        Ok(Asked::Resolver(_)) | Err(_) => crate::error::AGAIN_NUMBER,
    };
    let dns = Component::Dns;
    trace::of(
        cx,
        dns,
        format_args!("[{queries}] hostip_resolv started -> {code}"),
    );
    if let Ok(Asked::Resolver(Some(q))) | Err(Some(q)) = asked {
        crate::conn::say_answered(q, name, at, addrs, &mut |parts| {
            trace::of_with(cx, dns, parts);
        });
    }
    if asked.is_err() {
        return;
    }
    if let Ok(Asked::Resolver(_)) = asked {
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
fn waiting<H: Host>(run: &mut Run, cx: &mut StepCx<'_, H>, until: Option<Instant>) {
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
fn arm<H: Host>(
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
fn up<H: Host>(
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
    names::connected(cx, crate::conn::chain::dns_filters(route, head));
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
    if race.is_some() {
        // The race's answer is let go as it ends.
        let kept = cx.rest.kept(cx.me, Kind::Names);
        cx.rest.net_names(cx.me, kept.as_ref()).1.release();
    }
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
    for filter in connected.going() {
        trace::of(cx, filter, format_args!("removing connected setup filter"));
        trace::of(cx, filter, format_args!("destroy"));
        if filter != Component::HttpsConnect {
            continue;
        }
        if let Some(lost) = lost.take() {
            trace::of(cx, Component::Setup, format_args!("destroy"));
            lost.discard(&mut DriveCx {
                step: cx,
                kept: None,
                deadlines: None,
            });
        } else if let Some(failed) = kept.take() {
            trace::of(cx, Component::Setup, format_args!("destroy"));
            failed.lose(&mut DriveCx {
                step: cx,
                kept: None,
                deadlines: None,
            });
        } else if first_failed {
            trace::of(cx, Component::Setup, format_args!("destroy"));
            trace::of(cx, Component::HappyEyeballs, format_args!("destroy"));
        }
    }
    assert!(lost.is_none(), "the HTTPS connect filter goes");
    let reduced = connected.reduced();
    mstate::trace(cx, format_args!("reduced to {reduced}"));
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
        ConnectError::Unresolved(why) => {
            match why {
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
                Unresolved::Resolver { queued, .. } => {
                    trace_lookup(cx, route, Some(Found::Resolved(Asked::Resolver(queued))));
                    trace_resolved(cx, route, Err(queued), &[]);
                }
                Unresolved::NoAddress(found) => {
                    trace_lookup(cx, route, Some(found));
                    if let Found::Stale(asked) | Found::Resolved(asked) = found {
                        trace_resolved(cx, route, Ok(asked), &[]);
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
                Unresolved::Resolver { explained, .. } => {
                    let kind = match explained {
                        Some(reason) => trace::fail_with(
                            cx,
                            kind,
                            &[what, host, b" (", reason.as_bytes(), b")"],
                        ),
                        None => trace::fail_with(cx, kind, &[what, host]),
                    };
                    trace::fail_with(cx, kind, &[what, host])
                }
                _ => trace::fail_with(cx, kind, &[what, host]),
            };
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
            trace::info_with(cx, &[b"Could not resolve: ", host, at]);
            if why == Unresolved::Negative {
                trace::info_with(cx, &[b"Could not resolve: ", host]);
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
    let ms = cx.easy().report().timings().since_single_ms(cx.rest.now);
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
fn report_resolved<H: Host>(cx: &mut StepCx<'_, H>, answer: &Answer, port: u16) {
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
fn timed_out<H: Host>(cx: &mut StepCx<'_, H>, phase: Phase, sized: bool) -> ErrorKind {
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

/// The report of a transfer completing, from before the request was
/// about to be sent or not (`mstate_enter_completed`, `Curl_pgrsCompleted`):
/// the times it took, if any.
fn enter_completed(
    report: &mut TransferReport,
    now: Instant,
    before_did: bool,
) -> [Option<(Timer, Marked)>; 3] {
    let t = report.timings_mut();
    let mut marks = [None; 3];
    if before_did {
        // The times a jump to the end skipped.
        let skipped = [
            Timer::PreTransfer,
            Timer::PostTransfer,
            Timer::StartTransfer,
        ];
        for (mark, timer) in marks.iter_mut().zip(skipped) {
            *mark = Some((timer, t.mark(timer, now)));
        }
    }
    t.completed(now);
    marks
}

/// `enter_completed` as the transfer steps, traced in COMPLETED.
fn complete<H: Host>(cx: &mut StepCx<'_, H>, now: Instant, before_did: bool) {
    mstate::enter(cx, MState::Completed);
    for (timer, marked) in enter_completed(cx.report_mut(), now, before_did)
        .into_iter()
        .flatten()
    {
        mstate::marked(cx, timer, marked);
    }
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

/// Begin the run of a transfer a server pushes, for `url`, its request
/// `proto` waiting for the response on the stream promised, on the
/// connection to `origin` that `lease` is a key to: alive, timed from
/// now, in PERFORMING at once (`Curl_multi_add_perform`,
/// `Curl_init_transfer`).
pub(crate) fn start_pushed<H: Host>(
    run: &mut Run,
    cx: &mut StepCx<'_, H>,
    url: &Url,
    (lease, origin): (ConnLease, Option<Origin>),
    proto: ProtoState,
) -> Result<(), ErrorKind> {
    let whole = url.get(Part::Url, GetOptions::NONE).map_err(url_error);
    run.state = TransferState::Exchanging(Attached {
        lease,
        proto,
        origin,
    });
    run.url = whole?;
    run.method = Method::Get;
    run.alive = true;
    // A socket callback's abort is the multi's death, which fails this
    // transfer with the rest; nothing more is for the push to do.
    match cx.rest.tell.came_alive(&mut *cx.rest.events) {
        Ok(()) | Err(super::Abort) => {}
    }
    let limits = cx.easy().options().limits;
    run.deadlines = Deadlines::new(limits.total, limits.connect);
    let now = cx.rest.now;
    cx.report_mut().restart(now);
    *cx.speedometer_mut() = Speedometer::default();
    cx.mark(Timer::StartOp);
    cx.report_mut()
        .set_url(url)
        .map_err(|OutOfMemory| ErrorKind::OutOfMemory)?;
    mstate::enter(cx, MState::Performing);
    Ok(())
}

/// A pushed transfer that could not begin fails as it next runs.
pub(crate) fn fail_pushed(run: &mut Run, kind: ErrorKind) {
    let state = std::mem::replace(&mut run.state, TransferState::Init);
    run.state = state.fail(kind);
}

/// C's pretransfer, once per transfer: the option's URL parsed for the
/// first request.
fn pretransfer<H: Host>(run: &mut Run, cx: &mut StepCx<'_, H>) -> Result<Url, ErrorKind> {
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
    run.first = None;
    run.method = cx.easy().options().method;
    run.course = Course::START;
    run.http = Inherited::new(cx.easy().options().http.version);
    let options = cx.easy().options();
    let (want, proxy_want) = (options.http.auth.0, options.proxy.auth.0);
    cx.easy_mut().auth.start(want, proxy_want);
    // The application's referer, until a redirect gives another.
    if let Some(given) = &cx.easy().options().http.custom.referer {
        let mut referer = Vec::new();
        referer
            .try_extend_from_slice(given)
            .map_err(|_| ErrorKind::OutOfMemory)?;
        cx.report_mut().set_referer(referer);
    }
    crate::proto::http::cookies::load(cx)?;
    read_resolve(cx)?;
    // The URL is a pattern if the options say so as each request starts;
    // the debug test build says so on request too (`Curl_pretransfer`).
    run.wildcard_match = cx.easy().options().line.ftp.wildcard
        || (cfg!(feature = "debug-hooks") && curl_os::env::is_set(b"CURL_DBG_FTP_WILDCARD"));
    if run.wildcard_match && run.wildcard.is_none() {
        let made = curl_alloc::try_box(crate::proto::ftp::Wildcard::new());
        run.wildcard = Some(made.map_err(|_| ErrorKind::OutOfMemory)?);
    }
    crate::proto::http::hsts::load(cx)?;
    // Taken as it is parsed, its text not read again.
    if let Some((_, copy)) = shared {
        return copy.map_err(url_error);
    }
    let options = cx.easy().options();
    match parse_url(options.url().expect("checked above"), options, false) {
        Ok(url) => Ok(url),
        Err(UrlRefused::Rejected(e)) => {
            // Reported as C's `state.url` holds it, the text given.
            let (given, path_as_is) = (
                options.url().expect("checked above"),
                options.url_rules.path_as_is,
            );
            let mut kept = Vec::new();
            kept.try_extend_from_slice(given)
                .map_err(|_| ErrorKind::OutOfMemory)?;
            cx.report_mut()
                .set_url_given(&kept, path_as_is)
                .map_err(|_| ErrorKind::OutOfMemory)?;
            Err(trace::fail(
                cx,
                url_error(e),
                format_args!("URL rejected: {e}"),
            ))
        }
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
                    trace::info_with(cx, &[b"Resolve IP address '", ip, b"' found is illegal"]);
                }
                let kind = ErrorKind::SetoptOptionSyntax;
                let why: [&[u8]; 3] = [b"Could not parse CURLOPT_RESOLVE entry '", line, b"'"];
                return Err(trace::fail_with(cx, kind, &why));
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
        let at = Text::<8>::clipped(format_args!(":{port}")).0;
        let at = at.bytes();
        if discarded {
            trace::info_with(cx, &[b"RESOLVE ", name, at, b" - old addresses discarded"]);
        }
        put.map_err(|OutOfMemory| ErrorKind::OutOfMemory)?;
        let kept: &[u8] = if permanent { b"" } else { b" (non-permanent)" };
        trace::info_with(
            cx,
            &[b"[DNS] added ", name, at, b":", given, b" to cache", kept],
        );
        if name == b"*" {
            trace::info(cx, format_args!("RESOLVE *:{port} using wildcard"));
            cx.easy_mut().wildcard_resolve = true;
        }
    }
    Ok(())
}

/// What follows a complete exchange, as its protocol decides; a
/// `Location:` not followed has where it would have led kept for the
/// application, as C's `FOLLOW_FAKE` keeps it at the end of the
/// exchange.
fn exchanged<H: Host>(
    run: &mut Run,
    x: &mut Attached,
    cx: &mut StepCx<'_, H>,
) -> Result<AfterRequest, ErrorKind> {
    match x
        .proto
        .exchanged(cx, &run.url, x.origin.as_deref(), &mut run.http)?
    {
        Ended::Then(next) => Ok(next),
        Ended::Unfollowed(location) => {
            keep_redirect_url(run, cx, location)?;
            Ok(AfterRequest::Complete)
        }
    }
}

/// The URL of the request just made, as it was parsed for it (C's
/// `state.uh`).
fn request_url<H: Host>(run: &Run, cx: &StepCx<'_, H>) -> Result<Url, ErrorKind> {
    let mut url = match parse_url(&run.url, cx.easy().options(), true) {
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
        .filter(|_| run.course.allows_port())
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
    let max = options.http.max_redirects.get();
    let mut base = match request_url(run, cx) {
        Ok(base) => base,
        Err(e) => return TransferState::Init.fail(e),
    };
    // A `.netrc` file's credentials are the URL's from here, so that a
    // redirect on the same origin carries them as its own.
    if let Some(found) = proto.netrc_login() {
        let encoded = crate::url::SetOptions {
            parse: crate::url::ParseOptions {
                url_encode: true,
                ..crate::url::ParseOptions::NONE
            },
            ..crate::url::SetOptions::NONE
        };
        let secret = found.secret();
        let set = base
            .set(Part::User, Some(secret.user()), encoded)
            .and_then(|()| base.set(Part::Password, Some(secret.password()), encoded));
        if let Err(e) = set {
            return TransferState::Init.fail(url_error(e));
        }
    }
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
        run.course.drop_port();
    }
    let text = match url.get(Part::Url, GetOptions::NONE) {
        Ok(text) => text,
        Err(e) => return TransferState::Init.fail(url_error(e)),
    };
    // The body is started over before anything else is said of the next
    // request (`Curl_req_soft_reset`); a failure stands only if the next
    // request would send it.
    if proto.rewinds_upload() {
        client_start(cx);
    }
    let rewound = proto.rewind_upload(cx);
    trace::info_with(cx, &[b"Issue another request to this URL: '", &text, b"'"]);
    let switched = proto.redirected(cx, code, &mut run.method, &mut run.http);
    if let Err(e) = rewound
        && !switched
    {
        return TransferState::Init.fail(e);
    }
    // Parsed again for its leg, as every request's URL is.
    let url = match parse_url(&text, cx.easy().options(), true) {
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
/// retry does (`Curl_http_follow`, `FOLLOW_RETRY`), and a leg started. A
/// protocol without HTTP's follow is simply connected for again, its URL
/// as it was, nothing said and nothing counted (`multi_follow`).
fn retry_leg<H: Host>(
    run: &mut Run,
    cx: &mut StepCx<'_, H>,
    proto: &mut ProtoState,
) -> TransferState {
    let url = match parse_url(&run.url, cx.easy().options(), true) {
        Ok(url) => url,
        Err(UrlRefused::Rejected(e)) => {
            let kind = url_error(e);
            let why = format_args!("The redirect target URL could not be parsed: {e}");
            return TransferState::Init.fail(trace::fail(cx, kind, why));
        }
        Err(UrlRefused::Failed(kind)) => return TransferState::Init.fail(kind),
    };
    if !proto.follows() {
        mstate::enter(cx, MState::Setup);
        return start_leg(run, cx, url, true);
    }
    let shown = match url.get(Part::Url, GetOptions::NONE) {
        Ok(shown) => shown,
        Err(e) => return TransferState::Init.fail(url_error(e)),
    };
    // As for a redirect, which never switches to GET here. A retry always
    // rewinds (`Curl_retry_request`).
    client_start(cx);
    let rewound = proto.rewind_upload(cx);
    trace::info_with(cx, &[b"Issue another request to this URL: '", &shown, b"'"]);
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

/// The next request of a transfer, made again or redirected, for `url`:
/// counted in the header store, timed, and its leg started.
fn next_leg<H: Host>(run: &mut Run, cx: &mut StepCx<'_, H>, url: Url) -> TransferState {
    cx.report_mut().headers_mut().next_request();
    cx.mark(Timer::Redirect);
    // The sizes to come are the new request's (`Curl_pgrsResetTransferSizes`).
    let sizes = cx.report_mut().sizes_mut();
    sizes.download_expected = None;
    sizes.upload_expected = None;
    mstate::enter(cx, MState::Setup);
    start_leg(run, cx, url, false)
}

/// An `http` URL to a host the HSTS cache says to reach only over HTTPS
/// is switched to `https` (`hsts_upgrade`), after the application's port
/// is applied: the URL read back, port and all, is the transfer's and the
/// report's from then on.
fn hsts_upgrade<H: Host>(
    url: &mut Url,
    run: &mut Run,
    cx: &mut StepCx<'_, H>,
) -> Result<(), ErrorKind> {
    if cx.easy().hsts().is_none() {
        return Ok(());
    }
    let scheme = url.get(Part::Scheme, GetOptions::NONE).map_err(url_error)?;
    if !scheme.eq_ignore_ascii_case(b"http") {
        return Ok(());
    }
    // The host as it is looked up: an IPv6 address without its brackets,
    // a name in Unicode in its ASCII form (the origin's `hostname`).
    let host = url.get(Part::Host, GetOptions::NONE).map_err(url_error)?;
    let bare = host
        .strip_prefix(b"[")
        .and_then(|h| h.strip_suffix(b"]"))
        .unwrap_or(&host);
    let idn = cx.easy().libraries().idn;
    let ascii = crate::idn::lookup_name(idn, bare).map_err(crate::idn::IdnFailure::kind)?;
    let name = ascii.as_deref().unwrap_or(bare);
    if crate::proto::http::hsts::upgrade(url, name, cx)? {
        run.url = url.get(Part::Url, GetOptions::NONE).map_err(url_error)?;
        cx.report_mut()
            .set_url(url)
            .map_err(|OutOfMemory| ErrorKind::OutOfMemory)?;
    }
    Ok(())
}

/// Whether a request that got nothing back over a reused connection is
/// made again on a fresh one (`Curl_retry_request`): the connection may
/// have closed as it was reused. The fifth retry fails the transfer.
fn retry_request<H: Host>(
    run: &mut Run,
    x: &mut Attached,
    cx: &mut StepCx<'_, H>,
    ended: bool,
) -> Result<bool, ErrorKind> {
    let uploads = cx.easy().options().method == Method::Upload;
    let reused = x.proto.retryable(ended, uploads) && x.lease.conn().reused();
    // A stream HTTP/2 refused is safe to make again, on any connection,
    // if nothing came on it.
    let refused = x.proto.take_refused() && x.proto.retryable(ended, uploads);
    if !reused && !refused {
        return Ok(false);
    }
    if !reused {
        trace::info(cx, format_args!("REFUSED_STREAM, retrying a fresh connect"));
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
/// `url`, then the protocol connects over it. `rewinding` says a retry
/// asked for the readers to be rewound and nothing since did, as C's
/// `rewind_read` is left by a retry no follow handles.
fn start_leg<H: Host>(
    run: &mut Run,
    cx: &mut StepCx<'_, H>,
    mut url: Url,
    rewinding: bool,
) -> TransferState {
    // Cookies are counted from nothing for each request
    // (`Curl_req_hard_reset`).
    cx.easy_mut().set_cookies = 0;
    // The connect-to entries as the application's source has them now,
    // as C walks them for each connection it sets up; the header lists
    // are read as the request is built.
    if let Err(OutOfMemory) = cx.easy_mut().options_mut().connect_to.refill() {
        return TransferState::Init.fail(ErrorKind::OutOfMemory);
    }
    cx.report_mut().set_method(run.method);
    cx.mark(Timer::StartSingle);
    for (kind, at) in run.deadlines.start_leg(cx.rest.now).into_iter().flatten() {
        trace_set(cx, kind, at);
    }
    mstate::enter(cx, MState::Connect);
    // The request starts from nothing (`Curl_req_hard_reset`).
    upload::trace_reset(cx, rewinding);
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
    if let Err(kind) = hsts_upgrade(&mut url, run, cx) {
        return TransferState::Init.fail(kind);
    }
    let scheme = match url.get(Part::Scheme, GetOptions::NONE) {
        Ok(s) => s,
        Err(e) => return TransferState::Init.fail(url_error(e)),
    };
    // Known before the protocol opens anything, as C records it.
    cx.report_mut().set_protocol(Protocol::of_scheme(&scheme));
    // A URL, and a redirect the more so, goes only where the application
    // lets it (`url_set_conn_scheme`).
    let redirected = run.course.followed();
    let refused = !cx.easy().options().schemes.permit(&scheme, redirected);
    let follow: &[u8] = if redirected { b" (in redirect)" } else { b"" };
    // A scheme libcurl does not know is refused first, as the URL is
    // read (`Curl_peer_from_url`).
    if !ProtoState::knows(&scheme) {
        let kind = ErrorKind::UnsupportedProtocol;
        let why = [&b"Protocol \""[..], &scheme, b"\" not supported", follow];
        return TransferState::Init.fail(trace::fail_with(cx, kind, &why));
    }
    // A host name may be no longer than C lets a URL be (`MAX_URL_LEN`,
    // `Curl_peer_from_url`): the origin is made before anything is read
    // for it.
    if url.host_held().is_some_and(|host| host.len() > MAX_HOST) {
        let kind = ErrorKind::UrlMalformat;
        let kind = trace::fail_with(cx, kind, &[b"Too long hostname (maximum is 65535)"]);
        return TransferState::Init.fail(kind);
    }
    let started = if refused {
        Ok(None)
    } else {
        let before = Before {
            first: run.first.as_deref(),
            method: run.method,
            http: &run.http,
        };
        ProtoState::start(&scheme, &url, before, cx)
    };
    // A request made has read the `.netrc`, once. With none to make, C has
    // read it all the same, before it checks the protocol is built and
    // allowed.
    let started = match started {
        Ok(None) => crate::proto::netrc_unkept(&url, run.first.as_deref(), cx).map(|()| None),
        started => started,
    };
    // Out of the queue once the request knows its origin and its
    // credentials, before its protocol is checked and a connection looked
    // for (`Curl_connect`, after `url_set_data_origin_and_creds`).
    if started.is_ok() {
        cx.mark_now(Timer::PostQueue);
    }
    if let Ok(Some(proto)) = &started {
        proto.set_up_said(cx);
    }
    let proto = match started {
        Ok(Some(proto)) => proto,
        Ok(None) => {
            // A scheme libcurl knows that this build leaves out, or that
            // the options do not allow, or that names a proxy and carries
            // no transfer (`url_set_conn_scheme`).
            let carries = crate::conn::Scheme::named(&scheme).is_none_or(|s| !s.no_transfer());
            let tail: [&[u8]; 2] = if carries {
                [b"\" is disabled", follow]
            } else {
                [b"\" is not for transfers", b""]
            };
            let why = [&b"Protocol \""[..], &scheme, tail[0], tail[1]];
            let kind = trace::fail_with(cx, ErrorKind::UnsupportedProtocol, &why);
            return TransferState::Init.fail(kind);
        }
        Err(e) => return TransferState::Init.fail(e),
    };
    let target = proto.network(
        &url,
        cx.easy().options().address_scope,
        cx.easy().libraries().idn,
    );
    let target = match target {
        Ok(Some(target)) => target,
        Ok(None) => {
            let lease = match acquire(cx, &proto, Route::Local, Dial::Stream) {
                Ok(Acquired::New(lease)) => lease,
                Ok(Acquired::Reused(_)) => {
                    unreachable!("a connection without a network is never kept")
                }
                Ok(Acquired::Wait(_)) => {
                    unreachable!("a connection without a network has no limits")
                }
                Err(OutOfMemory) => return TransferState::Init.fail(ErrorKind::OutOfMemory),
            };
            // It moves nothing over a socket (`Curl_xfer_setup_nop`), and
            // has its name at once.
            mstate::xfer_setup(cx, Directions::default());
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
    if run.first.is_none() {
        run.first = Some(origin.clone());
    }
    // A Unix socket is connected to in place of the origin's host, and
    // of any connect-to entry, and no proxy is gone through
    // (`url_set_conn_origin_etc`).
    let unix = match unix_peer(cx, &origin) {
        Ok(unix) => unix,
        Err(e) => return TransferState::Init.fail(e),
    };
    let over_unix = unix.is_some();
    let mut alt_used = None;
    let mut preferred = None;
    let via = match unix {
        Some(peer) => Some(peer),
        None => match connect_to(cx, &origin) {
            Ok(Some(via)) => Some(via),
            // No connect-to entry: an alternative service, then.
            Ok(None) => {
                let neg = proto.negotiation();
                match alt_svc(cx, &origin, &scheme, neg) {
                    Ok(Some(AltSvc::Elsewhere { via, speaks })) => {
                        alt_used = Some(speaks);
                        Some(via)
                    }
                    Ok(Some(AltSvc::Here(alpn))) => {
                        preferred = Some(alpn);
                        None
                    }
                    Ok(None) => None,
                    Err(e) => return TransferState::Init.fail(e),
                }
            }
            Err(e) => return TransferState::Init.fail(e),
        },
    };
    let secured = proto.secured();
    let proxy = if over_unix {
        None
    } else {
        // A scheme not of HTTP's family, nor one a proxy takes as HTTP,
        // cannot be handed to an HTTP proxy (`PROTOPT_PROXY_AS_HTTP`).
        let handed = origin.scheme().proxies_as_http();
        match choose_proxy(cx, &origin, &scheme, via.is_some() || secured || !handed) {
            Ok(proxy) => proxy,
            Err(e) => return TransferState::Init.fail(e),
        }
    };
    // A request a proxy sends on names the whole URL, and the connection
    // is the proxy's (`origin_is_proxy`).
    let mut proto = proto;
    // The origin speaks another version too: it is wanted, and preferred.
    if let (Some(alpn), Some(neg)) = (preferred, proto.negotiation_mut()) {
        match alpn {
            crate::altsvc::Alpn::H1 => neg.wanted.h1 = true,
            crate::altsvc::Alpn::H2 => neg.wanted.h2 = true,
            crate::altsvc::Alpn::H3 => neg.wanted.h3 = true,
        }
        neg.alt_svc = Some(crate::proto::http::AltSvcSaid::Prefers(alpn));
    }
    if let Some(speaks) = alt_used {
        let via = via.as_deref().expect("an alternative is the peer");
        if let Err(OutOfMemory) = proto.alt_used(via, speaks) {
            return TransferState::Init.fail(ErrorKind::OutOfMemory);
        }
    }
    let origin = match &proxy {
        Some(p) if p.forward => {
            // A scheme a proxy takes as HTTP is asked of it in HTTP: the
            // connection's protocol is the proxy's (`conn->scheme`).
            let ftp = matches!(proto, ProtoState::Ftp(_));
            // `;type=` as the application's transfer text option says.
            let ftp_type = (ftp && cx.easy().options().proxy.transfer_mode).then(|| {
                if cx.easy().options().line.ftp.ascii {
                    b'a'
                } else {
                    b'i'
                }
            });
            if ftp {
                // The transfer's first request is this one if its origin
                // is the first one set, as the scheme's own request would
                // have been made before it was.
                let first = run.first.as_deref().filter(|f| !std::ptr::eq(*f, &*origin));
                let before = Before {
                    first,
                    method: run.method,
                    http: &run.http,
                };
                match crate::proto::http::Request::new(&url, false, before, cx)
                    .and_then(|r| curl_alloc::try_box(r).map_err(|_| ErrorKind::OutOfMemory))
                {
                    Ok(http) => proto = ProtoState::Http(http),
                    Err(e) => return TransferState::Init.fail(e),
                }
            }
            if let Err(e) = proto.forward(&url, ftp_type) {
                return TransferState::Init.fail(e);
            }
            // What the transfer says it spoke is the proxy's scheme
            // (`info.conn_scheme`, from `conn->scheme`).
            let spoken = Protocol::of_scheme(p.peer.scheme().name().as_bytes());
            cx.report_mut().set_protocol(spoken);
            p.peer.clone()
        }
        _ => origin,
    };
    // The settings its TLS is made with, which a connection must share
    // to serve it (`Curl_ssl_filter_config_tmp_init`).
    let tls = if secured {
        let defaults = cx
            .easy()
            .libraries()
            .tls
            .as_deref()
            .expect("a secured scheme is one a TLS library speaks")
            .ca_defaults();
        match crate::tls::TlsIdentity::of(&cx.easy().options().tls, defaults) {
            Ok(identity) => Some(identity),
            Err(OutOfMemory) => return TransferState::Init.fail(ErrorKind::OutOfMemory),
        }
    } else {
        None
    };
    // What few routes have: the local end each socket binds, which a
    // connection must share to serve it (`conn->interface_opts`,
    // `localport`, `localportrange`); the credentials a scheme that logs
    // in once per connection logs in with; the TLS a connection not over
    // it may be upgraded to, and how far TLS is asked for.
    let cold = match route_cold(cx, &mut proto, secured) {
        Ok(cold) => cold,
        Err(OutOfMemory) => return TransferState::Init.fail(ErrorKind::OutOfMemory),
    };
    let route = NetRoute {
        origin,
        via,
        ip: cx.easy().options().ip_version,
        proxy,
        tls,
        cold,
        // Compared for any protocol, as C compares it (`url_match_auth`).
        delegation: cx.easy().options().login.delegation,
    };
    let mut dial = Dial::Stream;
    // HTTP/3 alone must be possible (`Curl_http_setup_conn`), and is
    // dialed over QUIC, as the HTTPS connect's one attempt is
    // (`cf_hc_baller_assign`).
    let versions = proto.http_versions();
    if versions.h3_only() {
        if let Err(kind) = may_http3(cx, &route, secured) {
            return TransferState::Init.fail(kind);
        }
        dial = Dial::Quic;
    } else if https::HttpsConnect::heading(&route, cx.easy().options().tls.options.alpn).is_some()
        && https::Choosing::of(&proto, &route, cx)
            .first()
            .is_some_and(|(alpn, _)| alpn == https::Alpn::H3)
    {
        // The HTTPS connect filter's first attempt is HTTP/3's
        // (`cf_hc_set_baller1`).
        dial = Dial::Quic;
    }
    // TFTP sends its own datagrams, straight to its peer; through a
    // proxy, the tunnel refuses it (`TRNSPRT_UDP`, `tunnel_init`).
    if proto.sends_datagrams() && route.proxy.is_none() {
        dial = Dial::Udp;
    }
    if run.wildcard_match {
        proto.give_wildcard(&mut run.wildcard);
    }
    setup(cx, Plan { proto, route, dial })
}

/// What of the route for `proto`, `secured` or not, few routes have
/// (`RouteCold`), or none if none of it is there. The credentials of a
/// scheme that logs in once per connection move from the request to it,
/// their one owner (`url_set_conn_login`).
fn route_cold<H: Host>(
    cx: &mut StepCx<'_, H>,
    proto: &mut ProtoState,
    secured: bool,
) -> Result<Option<TryArc<crate::conn::RouteCold>>, OutOfMemory> {
    let options = cx.easy().options();
    let local = options.sockets.local.try_clone()?;
    let use_ssl = options.line.use_ssl;
    let reuses_tls = proto.scheme().is_some_and(crate::conn::Scheme::reuses_tls);
    let tls = cx.easy().libraries().tls.as_deref();
    let upgrade = match tls {
        Some(tls) if !secured && (reuses_tls || use_ssl.may()) => Some(
            crate::tls::TlsIdentity::of(&options.tls, tls.ca_defaults())?,
        ),
        _ => None,
    };
    let ftp = match proto {
        ProtoState::Ftp(_) => {
            let ftp = &options.line.ftp;
            Some(crate::conn::FtpSetup {
                account: ftp.account.as_deref().map(copy_bytes).transpose()?,
                alternative_to_user: ftp
                    .alternative_to_user
                    .as_deref()
                    .map(copy_bytes)
                    .transpose()?,
                ccc: ftp.ssl_ccc,
            })
        }
        _ => None,
    };
    let cold = crate::conn::RouteCold {
        local,
        login: proto.take_login()?,
        upgrade,
        use_ssl,
        ftp,
        ssh: proto.take_ssh_keys(),
    };
    if cold.is_empty() {
        return Ok(None);
    }
    TryArc::try_new(cold).map(Some)
}

/// A copy of `bytes`.
fn copy_bytes(bytes: &[u8]) -> Result<Vec<u8>, OutOfMemory> {
    let mut v = Vec::new();
    v.try_extend_from_slice(bytes)?;
    Ok(v)
}

/// Whether HTTP/3 may be spoken over `route`, to an origin `secured` or
/// not (`Curl_conn_may_http3`): failed as C fails it if not.
fn may_http3<H: Host>(
    cx: &mut StepCx<'_, H>,
    route: &NetRoute,
    secured: bool,
) -> Result<(), ErrorKind> {
    match quic_refused(route, secured) {
        None => Ok(()),
        Some((kind, why)) => Err(trace::fail(cx, kind, format_args!("{why}"))),
    }
}

/// Whether the HTTPS connect filter of a setup over `route` may make an
/// attempt in HTTP/3: with a QUIC library, where HTTP/3 may be spoken
/// (`cf_hc_may_h3`), through an HTTP proxy over its CONNECT-UDP.
fn may_quic<H: Host>(cx: &StepCx<'_, H>, route: &NetRoute) -> bool {
    cx.easy().libraries().h3.is_some() && quic_refused(route, true).is_none()
}

/// Why HTTP/3 may not be spoken over `route`, to an origin `secured` or
/// not, if it may not (`Curl_conn_may_http3`).
fn quic_refused(route: &NetRoute, secured: bool) -> Option<(ErrorKind, &'static str)> {
    Some(if route.destination().is_unix() {
        let why = "HTTP/3 cannot be used over UNIX domain sockets";
        (ErrorKind::QuicConnectError, why)
    } else if !secured {
        (
            ErrorKind::UrlMalformat,
            "HTTP/3 requested for non-HTTPS URL",
        )
    } else if route.socks().is_some() {
        (
            ErrorKind::UrlMalformat,
            "HTTP/3 is not supported over a SOCKS proxy",
        )
    } else {
        return None;
    })
}

/// The peer at the Unix socket the options name, if they name one,
/// spoken to as `origin` is (`Curl_peer_uds_create`): an empty path
/// fails the transfer, unsaid.
fn unix_peer<H: Host>(
    cx: &mut StepCx<'_, H>,
    origin: &Peer,
) -> Result<Option<TryArc<Peer>>, ErrorKind> {
    let Some(unix) = cx.easy().options().sockets.unix.as_ref() else {
        return Ok(None);
    };
    if unix.path.is_empty() {
        return Err(ErrorKind::FailedInit);
    }
    let oom = |OutOfMemory| ErrorKind::OutOfMemory;
    let mut path = Vec::new();
    path.try_extend_from_slice(&unix.path).map_err(oom)?;
    let peer = Peer::unix(origin.scheme(), path, 0, unix.abstract_name);
    TryArc::try_new(peer).map(Some).map_err(oom)
}

/// The proxy the transfer to `origin` goes through, if any
/// (`Curl_proxy_init_conn`): the options', or else the one the
/// environment names for `scheme`, unless the no-proxy list names the
/// origin's host; behind the SOCKS pre-proxy if one is set, which alone
/// is the proxy. Through a connect-to peer, or to a secured origin
/// (`tunnels`), an HTTP proxy would tunnel.
fn choose_proxy<H: Host>(
    cx: &mut StepCx<'_, H>,
    origin: &Peer,
    scheme: &[u8],
    tunnels: bool,
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
    // tunnel, or reaches the origin through another peer, or is secured,
    // or is of a scheme an HTTP proxy cannot be handed (`tunnels`).
    let tunnel = cx.easy().options().proxy.tunnel || tunnels;
    let route = ProxyRoute::new(kind, peer, creds, !tunnel, auth_only);
    let route = match pre {
        Some((kind, peer, creds)) => route
            .behind(PreProxy { kind, peer, creds })
            .map_err(|OutOfMemory| ErrorKind::OutOfMemory)?,
        None => route,
    };
    if !route.https() {
        return Ok(Some(route));
    }
    // The settings the HTTPS proxy's TLS is made with, which a
    // connection must share to serve the transfer
    // (`Curl_ssl_filter_config_tmp_init`'s `ssl_proxy`).
    let defaults = cx
        .easy()
        .libraries()
        .tls
        .as_deref()
        .expect("an HTTPS proxy is one only with a TLS library")
        .ca_defaults();
    let options = cx.easy().options();
    let identity = TlsIdentity::of_proxy(&options.proxy.tls, &options.tls.options, defaults)
        .map_err(|OutOfMemory| ErrorKind::OutOfMemory)?;
    let route = route
        .secured(identity)
        .map_err(|OutOfMemory| ErrorKind::OutOfMemory)?;
    Ok(Some(route))
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
    let tls = cx.easy().libraries().tls.is_some();
    let parsed = match proxy::parse(text, kind, options.port, tls) {
        Ok(parsed) => parsed,
        Err(Refused::OutOfMemory) => return Err(ErrorKind::OutOfMemory),
        Err(Refused::Syntax(e)) => {
            let e = Text::<256>::clipped(format_args!("': {e}")).0;
            return Err(trace::fail_with(
                cx,
                ErrorKind::CouldntResolveProxy,
                &[b"Unsupported proxy syntax in '", text, e.bytes()],
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
    // A name in Unicode is looked up by its ASCII form, as the origin's
    // (`Curl_peer_from_proxy_url`).
    let mut parsed = parsed;
    parsed.peer = parsed
        .peer
        .idn(cx.easy().libraries().idn)
        .map_err(crate::idn::IdnFailure::kind)?;
    // The URL's user and password, else the options' (`proxy_parse`);
    // either goes with the service the options name, which makes
    // credentials alone for a proxy that is not a pre-proxy.
    let options = &cx.easy().options().proxy;
    let from_url = parsed.user.is_some() || parsed.password.is_some();
    let (user, password) = if from_url || pre {
        (parsed.user, parsed.password)
    } else {
        (
            options.user.as_deref().map(copied).transpose()?,
            options.password.as_deref().map(copied).transpose()?,
        )
    };
    let service = match options.service.as_deref() {
        Some(service) if from_url || !pre => copied(service)?,
        _ => Vec::new(),
    };
    let creds = match (user, password) {
        (None, None) if service.is_empty() => None,
        (user, password) => Some(
            TryArc::try_new(ProxyCreds {
                user: user.unwrap_or_default(),
                password: password.unwrap_or_default(),
                service,
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
    let acquired = acquire(cx, &plan.proto, Route::Net(plan.route.clone()), plan.dial);
    if !matches!(acquired, Ok(Acquired::Wait(_))) {
        // One waiting may now find room too.
        schedule_pending(&mut cx.rest);
    }
    let lease = match acquired {
        Ok(Acquired::New(lease)) => lease,
        Ok(Acquired::Reused(lease)) => {
            let route = &plan.route;
            let name = route.origin.scheme().name();
            let (to, host): (&[u8], _) = match &route.proxy {
                Some(proxy) => (b": connection with proxy ", proxy.peer.shown()),
                None => (b": connection with host ", route.origin.name()),
            };
            // Attached as it is found, its TLS objects the handlers' from
            // the line that says so (`url_find_or_create_conn`).
            let slot = cx.rest.caches.pool.slot_of(&lease);
            cx.lent = native_of(slot.and_then(|s| s.query(LayerQuery::TlsNative)));
            trace::info_with(cx, &[b"Reusing existing ", name.as_bytes(), to, host]);
            plan.proto.reused(cx);
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
                WaitReason::Multiplex => trace::info(
                    cx,
                    format_args!("Waiting on connection to negotiate possible multiplexing."),
                ),
            }
            mstate::enter(cx, MState::Pending);
            return TransferState::Pending(plan);
        }
        Err(OutOfMemory) => return TransferState::Init.fail(ErrorKind::OutOfMemory),
    };
    cx.report_mut().set_used_proxy(plan.route.proxy.is_some());
    let Plan {
        proto,
        route,
        dial: _,
    } = plan;
    let mut https = None;
    if !lease.is_up() {
        // The HTTPS connect filter starts the chain, which puts the setup
        // filter below it as its attempt starts; or the setup filter does
        // (`Curl_cf_https_setup`, `Curl_cf_setup_insert_after`).
        https = https::HttpsConnect::heading(&route, cx.easy().options().tls.options.alpn);
        let first = match https {
            Some(_) => Component::HttpsConnect,
            None => Component::Setup,
        };
        trace::of(cx, first, format_args!("added"));
        let record = https.is_some_and(|h| h.asks());
        let wants_quic = proto.negotiation().is_some_and(|n| n.wants_quic());
        names::chain_set_up(cx, &route, record, wants_quic);
        mstate::trace(cx, format_args!("Curl_conn_setup() -> 0"));
    }
    TransferState::Connecting(Connecting {
        lease,
        proto,
        route,
        https,
        race: None,
        negotiate: None,
    })
}

/// Let the next transfer waiting for a connection, after the last one
/// let, look for one again (`multi_schedule_pending`): one at a time, as
/// a connection freed most often makes room for one.
pub(crate) fn schedule_pending<H: Host>(rest: &mut EngineRest<'_, H>) {
    if let Some(id) = wake_pending(rest.tell.slots, rest.dirty, rest.pending_after) {
        let mut cx = StepCx::new(id, rest.reborrow());
        mstate::enter(&mut cx, MState::Connect);
    }
}

/// As `schedule_pending`, on the multi's tables: the transfer let out,
/// which the caller traces entering CONNECT at once, as C's
/// `move_pending_to_connect` does, so that it is in the multi's process
/// set, and its pollset traced, before it next runs.
pub(super) fn wake_pending<H: Host>(
    slots: &mut Slots<H>,
    dirty: &mut RowSet,
    after: &mut Option<TransferId>,
) -> Option<TransferId> {
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
    let id = found?;
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
    Some(id)
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
            // A name in Unicode is looked up by its ASCII form, as the
            // origin's (`Curl_peer_from_connect_to`).
            let via = via.idn(cx.easy().libraries().idn);
            let via = via.map_err(crate::idn::IdnFailure::kind)?;
            return TryArc::try_new(via)
                .map(Some)
                .map_err(|OutOfMemory| ErrorKind::OutOfMemory);
        }
        Err(BadVia::OutOfMemory) => return Err(ErrorKind::OutOfMemory),
        Err(BadVia::Syntax { kind, why, text }) => {
            let why = why.as_bytes();
            (kind, trace::reason_with(&[why, b" in '", text, b"'"]))
        }
    };
    Err(trace::fail_for(cx, kind, reason))
}

/// What an alternative service for the origin says.
enum AltSvc {
    /// A connection goes to another peer, `via`, switching the request to
    /// `speaks` if that is another version than the one looked up.
    Elsewhere {
        via: TryArc<Peer>,
        speaks: Option<crate::altsvc::Alpn>,
    },
    /// The origin itself speaks this version too, which is preferred.
    Here(crate::altsvc::Alpn),
}

/// What an alternative service says of `origin`, if the cache is on and
/// knows one, for an `https` URL, or any in a debug build told
/// `CURL_ALTSVC_HTTP` (`url_set_conn_peer`). HTTP/3's alternative is
/// looked for first, then HTTP/2's, then HTTP/1's, as the request wants
/// them and the cache allows, those of HTTP/3 where a library speaks it.
fn alt_svc<H: Host>(
    cx: &mut StepCx<'_, H>,
    origin: &Peer,
    scheme: &[u8],
    neg: Option<crate::proto::http::Negotiation>,
) -> Result<Option<AltSvc>, ErrorKind> {
    use crate::altsvc::{Alpn, Versions};
    use crate::proto::http::Negotiation;
    let (Some(alt_svc), Some(neg)) = (cx.easy().alt_svc(), neg) else {
        return Ok(None);
    };
    let ctrl = alt_svc.ctrl().versions;
    let secured = scheme == b"https";
    #[cfg(feature = "debug-hooks")]
    let secured = secured || curl_os::env::is_set(b"CURL_ALTSVC_HTTP");
    if !secured {
        return Ok(None);
    }
    let (wanted, allowed) = (
        Negotiation::bits(neg.wanted),
        Negotiation::bits(neg.allowed),
    );
    trace::debug_info(
        cx,
        format_args!("Alt-svc check wanted={wanted:x}, allowed={allowed:x}"),
    );
    let h2 = cx.easy().libraries().h2.is_some();
    let h3 = cx.easy().libraries().h3.is_some();
    let allowed = Versions {
        h1: neg.allowed.h1 && ctrl.h1,
        h2: neg.allowed.h2 && h2 && ctrl.h2,
        h3: neg.allowed.h3 && h3 && ctrl.h3,
    };
    trace::debug_info_with(cx, &[b"check Alt-Svc for host '", origin.name(), b"'"]);
    let now = crate::date::cache_now(cx.unix_time());
    let alt_svc = cx.easy_mut().alt_svc_mut().expect("on, as above");
    let mut sources = [
        (neg.wanted.h3 && h3).then_some(Alpn::H3),
        (neg.wanted.h2 && h2 && !neg.prior).then_some(Alpn::H2),
        (neg.wanted.h1 && !neg.only_10).then_some(Alpn::H1),
    ]
    .into_iter()
    .flatten();
    let (src, found) = loop {
        let Some(src) = sources.next() else {
            return Ok(None);
        };
        if let Some(found) = alt_svc.lookup((origin.name(), origin.port(), src), allowed, now) {
            break (src, found);
        }
    };
    if found.same {
        return Ok(Some(AltSvc::Here(found.alpn)));
    }
    let oom = |OutOfMemory| ErrorKind::OutOfMemory;
    // An IPv6 address in brackets, as a peer holds one.
    let mut host = Vec::new();
    let parts: [&[u8]; 3] = match found.host.contains(&b':') {
        true => [b"[", found.host, b"]"],
        false => [b"", found.host, b""],
    };
    for part in parts {
        host.try_extend_from_slice(part).map_err(oom)?;
    }
    let (dst_alpn, port) = (found.alpn, found.port);
    let via = Peer::new(origin.scheme(), host, port, None);
    // A name in Unicode is looked up by its ASCII form, as the origin's
    // (`Curl_peer_create`).
    let via = via.idn(cx.easy().libraries().idn);
    let via = via.map_err(crate::idn::IdnFailure::kind)?;
    let mut line = trace::Line::new();
    line.text(format_args!("Alt-svc connecting from [{}]", src.name()));
    line.raw(origin.name());
    line.text(format_args!(":{} to [{}]", origin.port(), dst_alpn.name()));
    line.raw(via.name());
    line.text(format_args!(":{}", via.port()));
    trace::info_with(cx, &[line.bytes()]);
    let speaks = (src != dst_alpn).then_some(dst_alpn);
    let via = TryArc::try_new(via).map_err(oom)?;
    Ok(Some(AltSvc::Elsewhere { via, speaks }))
}

/// The search passed over connection `number`, as it speaks `version`,
/// which the transfer does not allow: the C debug build's line.
fn unwanted<H: Host>(
    cx: &mut StepCx<'_, H>,
    number: crate::conn::ConnNumber,
    version: crate::report::ResponseVersion,
) {
    use crate::report::ResponseVersion;
    let not = match version {
        ResponseVersion::Http3 => "h3",
        ResponseVersion::Http2 => "h2",
        ResponseVersion::Http10 | ResponseVersion::Http11 => "h1",
    };
    if cfg!(feature = "debug-hooks") {
        trace::info(
            cx,
            format_args!("not reusing conn {number}, we do not want {not}"),
        );
    }
}

/// A connection for the transfer making `proto`, and the trace of what
/// the search for one did.
/// `last` is the transfer's last connection, tried first and then
/// replaced by the one it gets.
fn acquire<H: Host>(
    cx: &mut StepCx<'_, H>,
    proto: &ProtoState,
    route: Route,
    dial: Dial,
) -> Result<Acquired, OutOfMemory> {
    let auth = &cx.easy().auth;
    let wants = match (proto, &route) {
        (ProtoState::Http(request), Route::Net(tcp)) => {
            request.reuse_wants(auth.host_want(), auth.proxy_want(), tcp)
        }
        _ => AuthWants::NONE,
    };
    let limits = cx.easy().options().limits.reuse;
    let rules = ReuseRules {
        max_idle: limits.max_idle.map(TimeLimit::duration),
        max_age: limits.max_age.map(TimeLimit::duration),
        // A redirect's request would reuse one anyway; one that only
        // connects never does (`url_attach_existing`).
        fresh: limits.fresh || cx.easy().options().connect_only.reserves(),
    };
    let mut notes = Vec::new();
    let now = cx.rest.now;
    let add = cx.rest.tell.limits.add();
    // The search and the addition, each a use of the pool of its own
    // (`Curl_cpool_find`, `Curl_cpool_add`).
    let home = match cx.rest.kept(cx.me, Kind::Connections) {
        Some(kept) => Home::Share(kept.share),
        None => Home::Multi,
    };
    let last = cx.easy().last_conn.map(|l| l.id);
    // What it allows, not only what it wants: a connection in HTTP/3 serves
    // one that asked for no version (`url_match_http_version`).
    let versions = proto.allowed_versions();
    // An HTTP transfer that may speak HTTP/2 or HTTP/3 shares a
    // connection that multiplexes, as the multi lets it
    // (`xfer_may_multiplex`).
    let http = matches!(proto, ProtoState::Http(_));
    let multiplex = (cx.rest.tell.limits.multiplex && http && (versions.h2 || versions.h3))
        .then_some(cx.rest.tell.limits.max_streams);
    let pipewait = cx.easy().options().http.pipewait;
    let found = if pool::searches(&route, rules) {
        let wanted = pool::Wanted {
            route: &route,
            auth: wants,
            last,
            versions,
            multiplex,
            pipewait,
            lending: pool::Lending::NONE,
        };
        // A share's connections lent to the multi are judged as the
        // multi's own, in the share's order.
        let lent = match &home {
            Home::Share(share) => Some(cx.rest.caches.pool.lending(share, &wanted)?),
            _ => None,
        };
        let wanted = pool::Wanted {
            lending: lent.as_ref().map_or(pool::Lending::NONE, |l| l.lending()),
            ..wanted
        };
        cx.rest.pool_search(cx.me, &home, |pool, exits, here| {
            pool.find(here, wanted, rules, exits, now, &mut notes)
        })?
    } else {
        pool::Found::Nothing
    };
    // Said as the search passes them over, before a connection is made or
    // attached, as C's debug build says it in `url_match_http_version`.
    notes.retain(|note| match *note {
        PoolNote::Unwanted { number, version } => {
            unwanted(cx, number, version);
            false
        }
        _ => true,
    });
    let acquired = match found {
        pool::Found::Lease(lease) => Acquired::Reused(lease),
        pool::Found::Lent(id) => {
            let Home::Share(share) = &home else {
                unreachable!("only a share lends");
            };
            Acquired::Reused(cx.rest.caches.pool.join_lent(share, id))
        }
        pool::Found::Wait => Acquired::Wait(pool::WaitReason::Multiplex),
        pool::Found::Nothing => {
            // The connection closes its sockets as the transfer making it
            // says, whoever closes them (url.c's `fclosesocket`).
            let closer = match &cx.easy().options().sockets.close {
                Some(close) => Closer::Hook(close.clone()),
                None => Closer::System,
            };
            // What the connection keeps of the transfer's settings: C's
            // defaults, as no option sets them.
            let settings = ConnSettings::DEFAULT;
            let (added, members) = cx.rest.pool_search(cx.me, &home, |pool, exits, here| {
                pool.add(here, route, dial, closer, settings, add, exits, now)
                    .map(|added| (added, pool.len()))
            })?;
            if let Acquired::New(lease) = &added {
                let n = lease.number().get();
                mstate::trace(
                    cx,
                    format_args!(
                        "[CPOOL] added connection {n}. The cache now contains {members} members"
                    ),
                );
            }
            added
        }
    };
    // The transfer's connection from now on (`Curl_attach_connection`).
    if let Acquired::Reused(lease) | Acquired::New(lease) = &acquired {
        cx.report_mut().set_conn(Some(lease.number()));
        cx.easy_mut().last_conn = Some(crate::easy::LastConn {
            id: lease.id(),
            used: false,
        });
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
            PoolNote::InputPending => trace::debug_info(
                cx,
                format_args!("connection has no transfer but input, not healthy"),
            ),
            PoolNote::Closed(n) => trace::info(cx, format_args!("shutting down connection {n}")),
            PoolNote::Unwanted { .. } => unreachable!("said as the search returns"),
            // The server's limit is said with no space before "reached",
            // as C says it.
            PoolNote::Full {
                number,
                users,
                peer,
            } => trace::info(
                cx,
                format_args!(
                    "connection {number}{}reached MAX_CONCURRENT_STREAMS({users}), skip",
                    if peer { "" } else { " " }
                ),
            ),
            PoolNote::Multiplexed => trace::info(cx, format_args!("Multiplexed connection found")),
            PoolNote::MaxConcurrent {
                number,
                max,
                in_use,
            } => trace_max_concurrent(cx, number, max, in_use),
            PoolNote::NotOpenEnough(n) => trace::info(
                cx,
                format_args!("Connection {n} is not open enough, cannot reuse"),
            ),
            PoolNote::PendingCandidate => trace::info(
                cx,
                format_args!("Found pending candidate for reuse and CURLOPT_PIPEWAIT is set"),
            ),
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
/// scheme where it has none (`parseurlandfillconn`). The transfer's
/// `own` URL, read back from one parsed already, keeps any space the
/// application's URL handle allowed, as C goes on from that handle
/// (`state.uh`, `follow_parse_url`'s `CURLU_ALLOW_SPACE`).
fn parse_url(url: &[u8], options: &Options, own: bool) -> Result<Url, UrlRefused> {
    let parse = ParseOptions {
        guess_scheme: true,
        non_support_scheme: true,
        disallow_user: options.url_rules.disallow_user,
        path_as_is: options.url_rules.path_as_is,
        allow_space: own,
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

#[cfg(test)]
mod tests {
    use super::*;

    /// The URL a transfer with `default` as its default protocol fetches.
    fn with_default(default: Option<&str>, url: &str) -> Result<Vec<u8>, ErrorKind> {
        let mut options = Options::default();
        options.set_url(Some(url.as_bytes())).unwrap();
        options
            .set_default_protocol(default.map(str::as_bytes))
            .unwrap();
        let url = parse_url(url.as_bytes(), &options, false).map_err(|e| match e {
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
