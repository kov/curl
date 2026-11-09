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
use crate::conn::io::{Closer, Events, Remote, ResolveFailure, SocketKey};
use crate::conn::layer::{LayerAnswer, LayerCx, LayerQuery};
use crate::conn::pool;
use crate::conn::proxy::{self, Refused};
use crate::conn::shutdown::ConnSettings;
use crate::conn::{
    Acquired, Addresses, Answer, Asked, BadEntry, BadVia, Conn, ConnLease, ConnSlot, ConnectError,
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

mod connecting;
pub(crate) use connecting::*;
mod cx;
pub(crate) use cx::*;
mod h2tunnel;
mod h3tunnel;
use h3tunnel::Tunnels;
mod haproxy;
mod https;
mod leg;
pub(crate) use leg::*;
mod names;
pub(crate) use names::{async_gone, async_kept, async_shut};
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

use super::cx::{DriveCx, EngineRest, EventCx, TransferCalls, TransferCx};
use super::mstate::{self, MState};
use super::pending::PendingQueue;
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
    /// is up. The plan it looks again with is in the multi's queue of
    /// those waiting, which holds one for each transfer in this state.
    Pending,
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
    /// The resolve of the name its setup went on beside, if it failed
    /// with one going on: let go of with the setup's attempts.
    name: crate::conn::Late,
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

#[derive(Debug)]
/// Whether its message is read is the multi's to know (`Tally`).
pub(crate) struct Completed {
    pub(crate) outcome: Result<(), ErrorKind>,
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

    /// Whether the transfer's connection goes through a tunnel that is a
    /// stream of an HTTP/2 session with its proxy, made or being made
    /// (`[H2-PROXY]`).
    fn tunnels_h2(&self, pool: &Pool) -> bool {
        let answer = match self {
            TransferState::Done(_) => None,
            TransferState::Connecting(c) => {
                if matches!(
                    c.lead_handshake(),
                    Some(connecting::Handshake::H2Connect(_))
                ) {
                    return true;
                }
                c.query(LayerQuery::Tunnel)
            }
            state => state
                .slot(pool)
                .and_then(|slot| slot.query(LayerQuery::Tunnel)),
        };
        answer == Some(LayerAnswer::Tunnel(Component::H2Proxy))
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

    /// Tell the request its transfer's receiving was paused or unpaused
    /// (`Curl_conn_ev_data_pause`): an HTTP/2 stream's window is set for
    /// it at once, the connection out of its place meanwhile, unless
    /// another transfer's step has it out; then the stream's next read
    /// sets it.
    pub(crate) fn data_pause<H: Host>(&mut self, cx: &mut StepCx<'_, H>, paused: bool) {
        let Some(Attached {
            proto: ProtoState::Http(req),
            lease,
            ..
        }) = self.attached_mut()
        else {
            return;
        };
        if !req.h2_paused(paused) || cx.rest.caches.pool.slot_of(lease).is_none() {
            return;
        }
        cx.rest.caches.pool.check_out(lease);
        req.h2_data_pause(cx, lease, paused);
        cx.rest.caches.pool.check_in(lease);
    }

    /// Whether the request under way holds output for the application.
    #[cfg(debug_assertions)]
    pub(crate) fn holds_output(&self) -> bool {
        self.attached().is_some_and(|x| x.proto.holds_output())
    }

    /// Whether its request's end waits for its protocol's last answer.
    #[cfg(debug_assertions)]
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
            TransferState::Init | TransferState::Pending | TransferState::Setup(_) => {
                TransferState::Completed(Completed { outcome: Err(err) })
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
                name: c.name,
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

    /// Its request is over otherwise than whole, which C ends within the
    /// call that ended it, in no state of its own.
    fn ends_unshown(&self) -> bool {
        matches!(self, TransferState::Done(_)) && self.c_state().is_none()
    }

    /// Where the transfer is in C's states, when the engine's say: a
    /// request ended otherwise than whole stays where it ended, as it is
    /// done with there.
    fn c_state(&self) -> Option<MState> {
        Some(match self {
            TransferState::Init => return None,
            TransferState::Pending => MState::Pending,
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
            // It waits no longer (`curl_multi_remove_handle`, multi.c:860).
            TransferState::Pending => {
                cx.rest
                    .pending
                    .take(cx.me)
                    .expect("a waiting transfer's plan is queued");
                return;
            }
            TransferState::Init | TransferState::Setup(_) | TransferState::Completed(_) => return,
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
                name: c.name,
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
            // Any resolve still going on is not wanted
            // (`Curl_resolv_shutdown_all`).
            names::asyncs_done(cx);
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
    let kept = cx.rest.kept(cx.me, Kind::Names);
    let (_, mut names) = cx.rest.net_names(cx.me, kept.as_ref());
    names.section(|dns| dns.prune(max_age));
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
    // The name's resolve goes first, as the first attempt's chain's DNS
    // filter would before its sockets (`Curl_resolv_destroy`).
    d.name.end();
    if let Some(race) = d.race.take() {
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
    }
    release(cx, d.lease, premature, stream_closed, d.origin.as_ref());
    // A resolve the setup still had went with it.
    cx.libraries_closed();
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
    // The DNS filters of a setup given up let go of what they hold
    // (`CF_CTRL_DATA_DONE`).
    names::filters_done(cx, None);
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
            // Made only to be traced (`infof`'s check first).
            if cx.verbose() {
                let conn = Text::<64>::clipped(format_args!("Connection {n} to host ")).0;
                let rest = Text::<24>::clipped(format_args!(":{} left intact", origin.port())).0;
                trace::info_with(cx, &[conn.bytes(), origin.shown(), rest.bytes()]);
            }
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
                if let Some(connecting::RecordLookup::Library(r)) = &c.record_lookup {
                    for (s, events) in r.wants() {
                        set.add(&**s, *events)?;
                    }
                }
                // The name's filter, above the attempts (`Curl_resolv_pollset`).
                for (s, events) in c.name.wants() {
                    set.add(s, events)?;
                }
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
                    let waits = x.proto.waits(phase, slot.line());
                    let events = slot.adjust_pollset(waits, None);
                    for s in slot.sockets() {
                        set.add(s, events)?;
                    }
                    // A second connection, set up beside it, waits for
                    // what its setup does (`ftp_domore_pollset`).
                    if let Some(side) = x.proto.side_pollset(Events::NONE, waits) {
                        for (s, events) in side {
                            set.add(s, events)?;
                        }
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
                    let interest = x.proto.interest(pause, slot.line());
                    let side_interest = x.proto.side_interest(pause);
                    let events = slot.adjust_pollset(interest, x.proto.stream_sending());
                    for s in slot.sockets() {
                        set.add(s, events)?;
                    }
                    // The data a second connection moves (`Curl_xfer_setup_recv`
                    // of `SECONDARYSOCKET`).
                    if let Some(side) = x
                        .proto
                        .side_pollset(side_interest, interest | side_interest)
                    {
                        for (s, events) in side {
                            set.add(s, events)?;
                        }
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
    for (s, events) in setup.resolve_wants() {
        set.add(s, events)?;
    }
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
    /// The connection goes through a tunnel that is a stream of an
    /// HTTP/2 session with the proxy.
    h2_proxy: bool,
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
    /// The sockets its resolves wait on, which the DNS filters above put
    /// in the pollset first (`Curl_resolv_pollset`), not a socket filter:
    /// counted with the others, but not said as theirs.
    resolver: Vec<SocketKey>,
}

impl SetupTrace {
    /// Whether `key` is a socket of the setup's own, not a resolve's.
    fn own(&self, key: SocketKey) -> bool {
        !self.resolver.contains(&key)
    }
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
                // The name's filter's sockets, ahead of the attempts', go
                // with the first's turn while it runs beside the lead.
                other: c.other().map_or(0, |m| {
                    let name = match c.beside() {
                        Some(Attempt::First) => c.name.wants().count(),
                        _ => 0,
                    };
                    name + m.racing_wants().count() + m.resolve_wants().count()
                }),
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
                resolver: resolver_sockets(c)?,
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
            h2_proxy: self.state.tunnels_h2(pool),
            timers: self.deadlines.in_order(),
            paused: (pause.send_paused(), pause.recv != RecvPause::Running),
        })
    }
}

/// The sockets the resolves of setup `c` wait on: the record's library's,
/// and each attempt's.
fn resolver_sockets(c: &Connecting) -> Result<Vec<SocketKey>, OutOfMemory> {
    let mut keys = Vec::new();
    if let Some(connecting::RecordLookup::Library(r)) = &c.record_lookup {
        for (s, _) in r.wants() {
            keys.try_push(s.key())?;
        }
    }
    for (s, _) in c.name.wants() {
        keys.try_push(s.key())?;
    }
    for a in [Attempt::First, Attempt::Second] {
        for (s, _) in c
            .attempt(a)
            .into_iter()
            .flat_map(ConnectMachine::resolve_wants)
        {
            keys.try_push(s.key())?;
        }
    }
    Ok(keys)
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
            h2_proxy: false,
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
        let own = |key: SocketKey| self.setup.as_ref().is_none_or(|s| s.own(key));
        let udp = |cx: &mut StepCx<'_, H>, sockets: &[(SocketKey, Events)], n: usize| {
            for &(key, _) in sockets.iter().filter(|(k, _)| own(*k)) {
                let fd = key.get();
                let line = format_args!("adjust_pollset, !active, POLLIN fd={fd}");
                trace::of(cx, Component::Udp, line);
            }
            if !sockets.is_empty() {
                eyeballs(cx, n);
            }
        };
        // The connection's own socket, under its TLS, past the resolves'.
        let socket = wants.iter().find(|(k, _)| own(*k));
        udp(cx, first, first.len());
        // The TLS filter puts its socket in for what its session waits
        // for (`Curl_ssl_adjust_pollset`).
        if let (Some(waits), Some(&(key, _))) = (self.tls, socket) {
            let fd = key.get();
            let line = match waits {
                TlsWait::Send => format_args!("adjust_pollset, POLLOUT fd={fd}"),
                TlsWait::Recv | TlsWait::Nothing => format_args!("adjust_pollset, POLLIN fd={fd}"),
            };
            trace::of(cx, Component::Ssl, line);
        }
        // The session with an HTTP/2 proxy says what it asks of the
        // socket, the layers above's wants with its own
        // (`cf_h2_proxy_adjust_pollset`).
        if let (true, Some(&(_, events))) = (self.h2_proxy, socket) {
            let (recv, send) = (events.contains(Events::IN), events.contains(Events::OUT));
            if recv || send {
                let (recv, send) = (u8::from(recv), u8::from(send));
                let line = format_args!("adjust_pollset, want_recv={recv} want_send={send} -> 0");
                trace::of(cx, Component::H2Proxy, line);
            }
        }
        // An HTTPS proxy's, below it, asked twice once an HTTP/1 tunnel
        // through it is made: by the tunnel's filter and on its own.
        if let (Some((waits, tunneled)), Some(&(key, _))) = (self.proxy_tls, socket) {
            let fd = key.get();
            for _ in 0..1 + u8::from(tunneled && !self.h2_proxy) {
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
            for &(key, _) in wants.iter().filter(|(k, _)| own(*k)) {
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
struct FdEvents(crate::conn::io::RawSocket, &'static str, &'static str);

impl fmt::Display for FdEvents {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "fd={} {}{}", self.0, self.1, self.2)
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
            name: crate::conn::Late::default(),
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
/// A connection of the multi's that changed since a step last looked is
/// said first, and lets one waiting look again (`multi_runsingle`'s
/// `multi_ischanged`).
pub(crate) fn step<H: Host>(run: &mut Run, cx: &mut StepCx<'_, H>) -> Wake {
    // A completed transfer's run is over: C's loop has ended
    // (`handle_completed`). A request ending otherwise than whole ends in
    // the step that ended it, as C's does (`is_finished`).
    if !run.state.is_completed() && !run.state.ends_unshown() && cx.rest.shutdowns.take_changed() {
        mstate::trace(cx, format_args!("multi changed, check CONNECT_PEND queue"));
        schedule_pending_from(run, cx);
    }
    if let Some(lease) = run.state.lease_mut() {
        cx.rest.caches.pool.check_out(lease);
    }
    cx.lent = run.state.tls_native(Some(&cx.rest.caches.pool));
    let wake = step_lent(run, cx);
    cx.lent = None;
    // A connection found to multiplex is news to the multi, once: one
    // waiting may join it, as it looks again when a step next starts
    // (`Curl_conn_set_multiplex`).
    if let Some(x) = run.state.attached_mut()
        && x.lease.multiplexes()
        && x.lease.get().tell_multiplex()
    {
        cx.rest.shutdowns.conn_changed();
    }
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
        match lease.home() {
            _ if attached => {}
            Home::Multi => pool.settle(&Home::Multi, lease, settled),
            home @ Home::Share(share) => share.pool().settle(home, lease, settled),
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
        TransferState::Pending => pending(run, cx),
        TransferState::Setup(mut plan) => {
            // Let out of PENDING by another transfer (`multi_schedule_pending`).
            mstate::enter(cx, MState::Connect);
            // The request starts over (`Curl_req_hard_reset`). It keeps no
            // resolve's record: it waits before any lookup, and its leg
            // let go of those of the request before as it started.
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
                Ok(Connect::Waiting) => (TransferState::ProtoConnecting(x), Wake::Idle),
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
            Ok(DoStep::Doing) => (TransferState::Doing(x), Wake::Idle),
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
            Ok(DoStep::More) => (TransferState::DoingMore(x), Wake::Idle),
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
        TransferState::Did(x) => {
            // Over a connection that multiplexes, one waiting may join it
            // (`multistate_did`).
            if x.lease.multiplexes() {
                schedule_pending(&mut cx.rest);
            }
            // Output the application paused is still held, and delivered
            // in PERFORMING: C goes to DONE and drops it, the transfer
            // reported a success (an open question, MILESTONES step 70).
            if !x.proto.exchanges() && !x.proto.holds_output() {
                (
                    TransferState::Done(x.done(Ok(()), false, Reached::Made)),
                    Wake::Again,
                )
            } else {
                // With other transfers running, an HTTP request goes on
                // in the next pass, giving the others a chance to send
                // theirs first (`multistate_did`): its response is rarely
                // there yet.
                let http = x
                    .proto
                    .scheme()
                    .is_some_and(crate::conn::Scheme::http_family);
                let wake = if http && cx.running() > 1 {
                    Wake::Idle
                } else {
                    Wake::Again
                };
                (TransferState::Exchanging(x), wake)
            }
        }
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
                    Some(follow_leg(run, cx, proto, location, *code, *reload))
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
                let completed = TransferState::Completed(Completed { outcome: d.result });
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

/// A transfer in `state` whose pollset is adjusted for what its
/// connection holds (`multi_adjust_pollset`), from PROTOCONNECT to
/// PERFORMING but in RATELIMITING, which polls nothing: the transfer, and
/// the protocol's phase it waits in, none for its exchange.
pub(crate) fn input_polled(state: &mut TransferState) -> Option<(&mut Attached, Option<Waiting>)> {
    Some(match state {
        TransferState::ProtoConnect(x) | TransferState::ProtoConnecting(x) => {
            (x, Some(Waiting::Connecting))
        }
        TransferState::Do(x) | TransferState::Doing(x) => (x, Some(Waiting::Doing)),
        TransferState::DoingMore(x) => (x, Some(Waiting::More)),
        TransferState::Did(x) | TransferState::Exchanging(x) => (x, None),
        _ => return None,
    })
}

/// The transfer's pollset is made (`Curl_multi_pollset`), as the multi
/// waits or tells the socket callback: one that is to wait for input, as
/// its protocol says for its exchange or for the state it waits in, while
/// its connection holds some where a poll cannot see it, runs again in
/// the next pass, as C's pollset finds, says and marks it
/// (`multi_adjust_pollset`): in DID and PERFORMING, and from PROTOCONNECT
/// to DOING_MORE, which wait on the protocol's own pollset before the
/// layers adjust it, unless its receiving is over its limit. A step that
/// stopped reading short has marked it already (`ProtoStep::AtReadLimit`);
/// one whose read found nothing can still leave input held, taken in by
/// its sends, as a QUIC connection's are with its packets, or a read that
/// gave the last bytes of a response can leave the TLS session saying
/// more may come (`input_pending`).
pub(crate) fn buffered_input<H: Host>(run: &mut Run, cx: &mut StepCx<'_, H>) {
    if input_polled(&mut run.state).is_none() {
        return;
    }
    // A connection it shares is out of its place while it is looked at,
    // as for a step.
    if let Some(lease) = run.state.lease_mut() {
        cx.rest.caches.pool.check_out(lease);
    }
    marks_buffered(run, cx);
    if let Some(lease) = run.state.lease_mut() {
        cx.rest.caches.pool.check_in(lease);
    }
}

/// `buffered_input`'s look, its connection out.
fn marks_buffered<H: Host>(run: &mut Run, cx: &mut StepCx<'_, H>) {
    let Some((x, phase)) = input_polled(&mut run.state) else {
        return;
    };
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
fn pending<H: Host>(run: &mut Run, cx: &mut StepCx<'_, H>) -> (TransferState, Wake) {
    let now = cx.rest.now;
    match run.deadlines.time_left(starts(cx), now, Phase::Connecting) {
        TimeLeft::Expired(_) => {
            // Out of the queue as it looks again (`move_pending_to_connect`),
            // before its handlers hear of it: a transfer whose run is out
            // of its slot is never one to let out.
            let plan = cx
                .rest
                .pending
                .take(cx.me)
                .expect("a waiting transfer's plan is queued");
            timed_out(cx, Phase::Connecting, true);
            trace::info(cx, format_args!("PENDING handle timeout"));
            (TransferState::Setup(plan), Wake::Again)
        }
        TimeLeft::Remaining(_) | TimeLeft::Unlimited => (TransferState::Pending, Wake::Idle),
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
    // What can fail comes last: one that cannot start is taken out as a
    // transfer timed from its start, as C's stream setup fails after its
    // transfer's (`http2_data_setup` after `Curl_init_transfer`).
    run.url = whole?;
    cx.report_mut()
        .set_url(url)
        .map_err(|OutOfMemory| ErrorKind::OutOfMemory)?;
    mstate::enter(cx, MState::Performing);
    Ok(())
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
