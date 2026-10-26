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
    Acquired, Answer, Asked, BadEntry, BadVia, Conn, ConnLease, ConnSlot, ConnectError, Connected,
    Finish, Found, Full, Home, Limit, ListEntry, Made, Peer, Pool, PoolNote, PreProxy, Progress,
    ProxyCreds, ProxyRoute, Released, ReuseRules, Route, Setup, Tcp, Unresolved, WaitReason,
    parse_entry, queries,
};
use crate::deliver::{Directions, Pause, PauseRequest, Pipeline, RecvPause};
use crate::easy::Easy;
use crate::error::{ErrorKind, UrlErrorKind, url_error};
use crate::options::{Flow, Method, Options, ProxyType, ResolveList};
use crate::progress::rate::{RateLimits, Verdict, Way};
use crate::progress::{self, Speedometer};
use crate::share::Kind;

mod haproxy;
mod https;
mod socks;
mod tls;
mod tunnel;
use crate::components::Component;
use crate::proto::http::negotiate::Wants as AuthWants;
use crate::proto::http1::follow;
use crate::proto::http1::follow::Inherited;
use crate::proto::{Before, DoStep, Ended, ProtoState, ProtoStep};
use crate::report::{Ends, Marked, Starts, Timer, TransferReport};
use crate::time::{Instant, TimeLimit};
use crate::tls::{TlsIdentity, TlsNative, TlsWait};
use crate::trace::{self, Bytes, Ip, OsError};
use crate::upload::{self, Readers};
use crate::url::{self, GetOptions, ParseOptions, Part, SetOptions, Url};
use crate::version::Protocol;

use super::cx::{DriveCx, EngineRest, EventCx, TransferCalls, TransferCx};
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
    /// `Options::port` still applies: no redirect led to an absolute URL
    /// (`state.allow_port`).
    allow_port: bool,
    /// What HTTP's next request takes from the ones before it, kept for
    /// HTTP and not read here.
    http: Inherited,
    /// It has run its first step, and is neither done nor gone
    /// (`state.really_alive`).
    pub(crate) alive: bool,
}

impl Run {
    pub(crate) fn new() -> Run {
        Run {
            state: TransferState::Init,
            deadlines: Deadlines::new(None, None),
            url: Vec::new(),
            retries: 0,
            first: None,
            method: Method::Get,
            allow_port: true,
            http: Inherited::default(),
            alive: false,
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
    /// The HTTPS connect filter heading the setup, if it has one.
    https: Option<https::HttpsConnect>,
    /// HTTP Negotiate with the proxy a tunnel goes through, before the
    /// connection it belongs to is up: kept across a redial, as C keeps it
    /// on the connection whose filters it makes again, and handed to the
    /// connection as it comes up.
    negotiate: Option<Box<crate::proto::http::negotiate::Negotiate>>,
}

/// A handshake over the connection to the first hop: a proxy's, or the
/// origin's TLS.
#[derive(Debug)]
enum Handshake {
    Socks(socks::Socks),
    /// An HTTP proxy's tunnel, with `CONNECT`.
    Connect(tunnel::Tunnel),
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
            Handshake::Haproxy(_) => Component::Haproxy,
            Handshake::Tls(side) => side.filter(),
        }
    }

    /// What it waits for on the connection's socket, which `lease`
    /// holds: TLS's, what its layer says; the others', what they want as
    /// the layers below adjust it, an HTTPS proxy's TLS under a tunnel or
    /// the PROXY line.
    fn interest(&self, lease: &ConnLease) -> Events {
        match self {
            Handshake::Socks(s) => lease.handshake_pollset(s.interest()),
            Handshake::Connect(t) => lease.handshake_pollset(t.interest()),
            Handshake::Haproxy(p) => lease.handshake_pollset(p.interest()),
            Handshake::Tls(_) => lease.handshake_pollset(Events::NONE),
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
    result: Result<(), ErrorKind>,
    /// Ended before the request was complete.
    premature: bool,
    reached: Reached,
    /// The host connected to, if any, as a connection kept names it.
    origin: Option<Origin>,
    next: AfterRequest,
}

impl Done {
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
        let lease = self.lease()?;
        let slot = match pool {
            Some(pool) => pool.slot_of(lease)?,
            // Without the pool, a key in its place cannot be reached.
            None => lease.holding()?,
        };
        native_of(slot)
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
                matches!(c.lease.reached(), Some(SetupPoint::Dialed(m)) if m.has(Made::TUNNEL))
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
        let slot = match self {
            TransferState::Done(_) => None,
            state => state.slot(pool),
        }?;
        match slot.query(q)? {
            LayerAnswer::TlsWaits(TlsWait::Nothing) => None,
            LayerAnswer::TlsWaits(waits) => Some(waits),
            LayerAnswer::TlsNative(_) | LayerAnswer::Alpn(..) => {
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
            TransferState::Do(_) => MState::Do,
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

    /// Take the transfer out of the multi before it completed: give back
    /// its connection, as a premature end (`curl_multi_remove_handle`).
    pub(crate) fn abandon<H: Host>(self, cx: &mut StepCx<'_, H>) {
        // Past its request, the connection is in no known state
        // (`curl_multi_remove_handle`'s `streamclose`).
        let (lease, origin, past_do, rewinding) = match self {
            TransferState::Init
            | TransferState::Pending(_)
            | TransferState::Setup(_)
            | TransferState::Completed(_) => return,
            TransferState::Connecting(c) => (c.lease, Some(c.route.origin), false, false),
            TransferState::ProtoConnect(x) | TransferState::Do(x) => {
                let rewinding = x.proto.rewinds_upload();
                (x.lease, x.origin, false, rewinding)
            }
            TransferState::Did(x)
            | TransferState::Exchanging(x)
            | TransferState::RateLimiting(x) => {
                let rewinding = x.proto.rewinds_upload();
                (x.lease, x.origin, true, rewinding)
            }
            TransferState::Done(d) => {
                let rewinding = d.rewinding();
                (d.lease, d.origin, true, rewinding)
            }
        };
        mstate::trace(cx, format_args!("multi_done: status: 0 prem: 1 done: 0"));
        upload::trace_reset(cx, rewinding);
        release(cx, lease, true, past_do, origin.as_ref());
    }
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
    let finish = Finish {
        premature,
        forbid_reuse: cx.easy().options().limits.reuse.forbid,
        reserve: cx.easy().options().connect_only.reserves(),
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
    let home = lease.home().clone();
    let closes = lease.closes() || stream_closed;
    let multiplex = u8::from(lease.is_h2());
    let released = cx.rest.pool_section(cx.me, &home, |pool, exits, here| {
        let mut lease = lease;
        pool.check_in(&mut lease);
        pool.release(here, lease, finish, limit, exits, now)
    });
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
    if let Released::Closed(n) | Released::Terminated(n) = &released {
        // A connection to no host, a file's, has an empty name.
        let (host, port) = origin.map_or((Bytes(b""), 0), |o| (Bytes(o.name()), o.port()));
        mstate::trace(
            cx,
            format_args!(
                "multi_done, terminating conn {n} to {host}:{port}, forbid={}, close={}, premature={}, conn_multiplex={multiplex}",
                u8::from(finish.forbid_reuse),
                u8::from(closes),
                u8::from(finish.premature)
            ),
        );
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
            let (host, port) = (Bytes(origin.shown()), origin.port());
            trace::info(
                cx,
                format_args!("Connection {n} to host {host}:{port} left intact"),
            );
        }
        Released::Closed(n) => trace::info(cx, format_args!("shutting down connection {n}")),
        Released::Terminated(n) => trace::info(cx, format_args!("closing connection {n}")),
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
    pub(crate) fn pollset<'a>(&'a self, pause: Pause, pool: &'a Pool) -> Pollset<'a> {
        let mut set = Pollset::new();
        match self {
            TransferState::Connecting(c) if pause.recv == RecvPause::Running => {
                // A handshake waits for what it sends or reads, and to read
                // too, as the socket's filter, connected but not yet in
                // use, adds (`cf_socket_adjust_pollset`).
                let events = match c.handshake.as_ref() {
                    Some(h) => h.interest(&c.lease) | Events::IN,
                    None => Events::OUT,
                };
                for s in c.lease.sockets() {
                    set.add(s, events);
                }
            }
            TransferState::Exchanging(x) => {
                // A connection another transfer's step has out waits for
                // nothing of this one's until it is back.
                if let Some(slot) = pool.slot_of(&x.lease) {
                    let events = slot.adjust_pollset(x.proto.interest(pause));
                    for s in slot.sockets() {
                        set.add(s, events);
                    }
                }
            }
            _ => {}
        }
        set
    }
}

/// What a transfer's pollset trace says, read from its run before the
/// trace calls out, so the run stays in its slot meanwhile
/// (`Curl_multi_pollset`).
pub(crate) struct PollsetTrace<T> {
    wants: Wants,
    /// While the setup runs: whether its sockets are connected, a
    /// handshake under way over the one dialed, what their filter traces
    /// as, and whether an HTTPS connect filter heads it.
    setup: Option<(bool, Component, bool)>,
    /// What the origin's TLS session waits for, if it waits.
    tls: Option<TlsWait>,
    /// What an HTTPS proxy's waits for, if it waits, and whether a tunnel
    /// through it is made.
    proxy_tls: Option<(TlsWait, bool)>,
    timers: T,
    /// Sending and receiving, paused.
    paused: (bool, bool),
}

impl Run {
    /// What the transfer's pollset trace says, its pause `pause`.
    pub(crate) fn pollset_trace(
        &self,
        pause: Pause,
        pool: &Pool,
    ) -> PollsetTrace<impl Iterator<Item = (Instant, TimerKind)> + Clone + use<>> {
        let wants = self.state.pollset(pause, pool).wants();
        let setup = match &self.state {
            TransferState::Connecting(c) => Some((
                matches!(c.lease.reached(), Some(SetupPoint::Dialed(_))),
                c.route.socket_component(),
                c.https.is_some(),
            )),
            _ => None,
        };
        PollsetTrace {
            wants,
            setup,
            tls: self.state.tls_waits(pool),
            proxy_tls: self.state.proxy_tls_waits(pool),
            timers: self.deadlines.in_order(),
            paused: (pause.send_paused(), pause.recv != RecvPause::Running),
        }
    }
}

impl PollsetTrace<std::iter::Empty<(Instant, TimerKind)>> {
    /// The pollset of a transfer that waits on nothing and has no timer,
    /// its pause `pause`: one taken out of the multi.
    pub(crate) fn gone(pause: Pause) -> Self {
        PollsetTrace {
            wants: Wants::NONE,
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
        let wants = self.wants.as_slice();
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
        if let Some((dialed, component, https)) = self.setup {
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
            // The HTTPS connect filter, not connected while the setup
            // runs, says how many sockets the pollset has below it
            // (`cf_hc_adjust_pollset`).
            if https {
                let n = wants.len();
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
        match wants {
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
    /// The connection is up: on to the protocol's connect.
    fn attached(self) -> TransferState {
        let Connecting {
            lease,
            proto,
            route,
            handshake: _,
            https: _,
            negotiate,
        } = self;
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

/// A layer working for the stepping transfer traces as it does.
impl<H: Host> LayerCx for StepCx<'_, H> {
    fn now(&self) -> Instant {
        self.rest.now
    }

    fn of(&mut self, component: Component, line: std::fmt::Arguments<'_>) {
        trace::of(self, component, line);
    }

    fn info(&mut self, line: std::fmt::Arguments<'_>) {
        trace::info(self, line);
    }

    fn socket_failed(&mut self, e: &std::io::Error) {
        self.report_mut().socket_failed(e);
    }

    fn fails(&mut self, kind: ErrorKind, why: std::fmt::Arguments<'_>) -> ErrorKind {
        trace::fail(self, kind, why)
    }

    fn bytes(&mut self, kind: crate::handler::DebugKind, bytes: &[u8]) {
        trace::bytes(self, kind, bytes);
    }

    fn debugs(&self) -> bool {
        let options = self.easy().options();
        options.callbacks.debug.is_some() && options.output.verbose
    }

    fn verbose(&self) -> bool {
        self.easy().options().output.verbose
    }

    fn certinfo_report(&mut self) -> Option<&mut TransferReport> {
        let asked = self.easy().options().tls.certinfo;
        asked.then(|| self.report_mut())
    }

    fn tls_verified(&mut self, filter: Component, result: i64) {
        if filter == Component::SslProxy {
            self.report_mut().set_proxy_verify_result(result);
        } else {
            self.report_mut().set_verify_result(result);
        }
    }

    fn configures_tls(&self) -> bool {
        self.easy().options().tls.options.context.is_some()
    }

    /// The handler is given the context, which the transfer's handlers
    /// reach meanwhile as its connection's (`CURLINFO_TLS_SESSION`).
    fn configure_tls(&mut self, native: TlsNative) -> Result<(), ErrorKind> {
        let Some(handler) = self.easy().options().tls.options.context.clone() else {
            return Ok(());
        };
        let lent = self.lent.replace(native);
        let configured = handler.configure(&mut TransferCx::new(self), native);
        self.lent = lent;
        configured
    }

    fn pause_recv(&mut self) {
        let slot = self.rest.tell.slots.get_mut(self.me);
        slot.expect("the stepping transfer").pause.stop_recv();
    }

    fn unix_time(&self) -> i64 {
        self.rest.clock.unix_time()
    }

    /// A multi always has one.
    fn has_tls_sessions(&self) -> bool {
        true
    }

    /// The share's if it keeps them (`cf_ssl_scache_get`), what it says
    /// held until its lock is let go, as nothing is called out from inside
    /// a share's lock; else the multi's, lent out of the multi for the
    /// call, so the context traces through while `f` holds it.
    fn tls_sessions(&mut self, f: &mut dyn FnMut(&mut crate::tls::SessionCache, &mut dyn LayerCx)) {
        use crate::share::watched;
        if let Some(kept) = self.rest.kept(self.me, Kind::SslSessions) {
            let mut held = HeldSays {
                now: self.rest.now,
                unix: self.rest.clock.unix_time(),
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
                trace::of(self, Component::Ssls, format_args!("{line}"));
            }
            if let Some((kind, why)) = held.failure {
                trace::fail(self, kind, format_args!("{why}"));
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
struct HeldSays {
    now: Instant,
    unix: i64,
    /// The transfer traces the cache's lines (`ssls`).
    traces: bool,
    lines: Vec<String>,
    failure: Option<(ErrorKind, String)>,
}

impl LayerCx for HeldSays {
    fn now(&self) -> Instant {
        self.now
    }

    fn of(&mut self, component: Component, line: std::fmt::Arguments<'_>) {
        if self.traces
            && component == Component::Ssls
            && let Ok(line) = curl_alloc::try_format(line)
        {
            // Without memory to hold it, the line is not said, as a line
            // too long for the trace is cut.
            let _ = self.lines.try_push(line);
        }
    }

    fn info(&mut self, _: std::fmt::Arguments<'_>) {}

    fn fails(&mut self, kind: ErrorKind, why: std::fmt::Arguments<'_>) -> ErrorKind {
        if self.failure.is_none()
            && let Ok(why) = curl_alloc::try_format(why)
        {
            self.failure = Some((kind, why));
        }
        kind
    }

    fn unix_time(&self) -> i64 {
        self.unix
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
        }
    }
}

impl<H: Host> StepCx<'_, H> {
    /// Run `f` with transfer `id`'s step context and its HTTP request, its
    /// run out of its slot meanwhile, as the stepping transfer hands it
    /// what the connection they share did for it (ENGINE.md 4.4); the
    /// connection's TLS objects, the same, are lent to it, and it is
    /// stepped again in the pass. None if it is gone or makes no HTTP
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
    /// for a transfer the server pushes on it.
    pub(crate) fn pushed_lease(&mut self, lease: &mut ConnLease) -> ConnLease {
        self.rest.caches.pool.pushed(lease)
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

/// The TLS library's objects of the origin's connection `lease` holds.
pub(super) fn tls_native(lease: &ConnLease) -> Option<TlsNative> {
    native_of(lease.held())
}

/// The TLS library's objects of the origin's connection `slot`.
fn native_of(slot: &ConnSlot) -> Option<TlsNative> {
    match slot.query(LayerQuery::TlsNative)? {
        LayerAnswer::TlsNative(native) => Some(native),
        LayerAnswer::Alpn(..) | LayerAnswer::TlsWaits(_) => {
            unreachable!("an answer of another question")
        }
    }
}

/// Ask the connection `lease` holds, from its filter `top`, what was
/// agreed by ALPN (`Curl_conn_cf_get_alpn_negotiated`): the filter says it
/// is asked, and the TLS session, if one answers, what it answers; the
/// others answer none, or pass the question on, saying nothing.
pub(crate) fn query_alpn<H: Host>(
    cx: &mut StepCx<'_, H>,
    lease: &ConnLease,
    top: Component,
) -> Option<crate::tls::Chosen> {
    trace::of(cx, top, format_args!("query ALPN"));
    // An HTTPS proxy's TLS answers only when asked first: a tunnel's
    // filter above it keeps the question (`cf_h1_proxy_query`).
    if let Some(LayerAnswer::Alpn(chosen, filter)) = lease.query(LayerQuery::Alpn)
        && (filter != Component::SslProxy || top == Component::SslProxy)
    {
        let name = chosen.map_or("(nil)", crate::tls::Chosen::name);
        let line = format_args!("query ALPN: returning '{name}'");
        trace::of(cx, filter, line);
        return chosen;
    }
    None
}

/// Replay a transfer's held output, from outside its step.
pub(crate) fn flush<H: Host>(run: &mut Run, cx: &mut StepCx<'_, H>) -> Result<(), ErrorKind> {
    cx.lent = run.state.tls_native(Some(&cx.rest.caches.pool));
    let flushed = match run.state.pipeline_mut() {
        Some(p) => p.flush(cx),
        None => Ok(()),
    };
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
            && lease.is_h2()
        {
            cx.rest.caches.pool.attach(lease);
            // One waiting to multiplex may join it now
            // (`Curl_conn_set_multiplex`).
            schedule_pending(&mut cx.rest);
            return wake;
        }
    }
    let settled = run.state.attached().is_some_and(|x| x.proto.settled_conn());
    if let Some(lease) = run.state.lease_mut() {
        cx.rest.caches.pool.check_in(lease);
        if cx.rest.caches.pool.settle(lease, settled) {
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
                    start_leg(run, cx, url)
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
        // No protocol connects over its connection yet.
        TransferState::ProtoConnect(x) => (TransferState::Do(x), Wake::Again),
        // One that only connects is done once it has (`multistate_do`).
        TransferState::Do(x) if !cx.easy().options().connect_only.requests() => (
            TransferState::Done(x.done(Ok(()), false, Reached::Unmade)),
            Wake::Again,
        ),
        TransferState::Do(mut x) => match x.proto.do_it(cx, &mut x.lease) {
            Ok(DoStep::More) => {
                within_do = true;
                (TransferState::Do(x), Wake::Again)
            }
            Ok(DoStep::Made) => {
                // About to send; sent already, with no body
                // (`mstate_enter_did`).
                mstate::enter(cx, MState::Did);
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
        // Out of time as the step starts, the request made: over
        // (`multi_handle_timeout`, ahead of the state's work).
        TransferState::Did(x) if expired(run, cx) => {
            let kind = timed_out(cx, Phase::Transferring, x.proto.sizes_request());
            (TransferState::Did(x).fail(kind), Wake::Again)
        }
        TransferState::Did(x) if !x.proto.exchanges() => (
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
            let stepped = x.proto.step(cx, &mut x.lease);
            if let Err(e) = stepped {
                sendrecv_failed(cx, e);
            }
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
                // A stream that said HTTP/1.1 is required is made again
                // in it, on a fresh connection, its failure let go
                // (`multistate_performing`).
                Err(ErrorKind::Http2Stream) if x.proto.h1_required() => {
                    trace::info(cx, format_args!("Downgrades to HTTP/1.1"));
                    run.http.downgrade();
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
        TransferState::Done(mut d) => {
            // Whether the request was cut short is decided by how it
            // ended, not by the protocol's last word (`multi_done`), which
            // comes first.
            let mut premature = d.premature || is_premature(d.result);
            // A failure other than its stream's closes an HTTP/2
            // connection, which outlives a request otherwise
            // (`multistate_performing`'s `streamclose`).
            if d.result.is_err_and(|e| e != ErrorKind::Http2Stream) && d.lease.is_h2() {
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
                d.result = proto.done(
                    cx,
                    &mut d.lease,
                    d.result,
                    premature,
                    &d.next,
                    &mut run.http,
                );
            }
            // A last progress pass, unless the transfer never connected
            // (C's `mstate > MSTATE_CONNECTING`) or a callback aborted
            // already: a failed connect draws no meter and calls no
            // handler.
            if d.proto.is_some()
                && d.result != Err(ErrorKind::AbortedByCallback)
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
            let stream_closed = d.premature && d.reached != Reached::Unmade;
            // The request is over (`Curl_req_done`), unless it failed.
            if d.result.is_ok() {
                upload::trace_reset(cx, d.rewinding());
            }
            release(cx, d.lease, premature, stream_closed, d.origin.as_ref());
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
                (AfterRequest::Follow { location, code }, Ok(()), Some(proto)) => {
                    Some(follow_leg(run, cx, proto, location, *code))
                }
                _ => None,
            };
            if let Some(next) = leg {
                if next.is_completed() {
                    complete(cx, now, true);
                }
                (next, Wake::Again)
            } else {
                complete(cx, now, d.reached == Reached::Unmade);
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
    if run.deadlines.any() {
        run.deadlines.clear_all();
        mstate::trace(cx, format_args!("[TIMEOUT] all cleared"));
    }
}

/// A pass over the transfer's connection failed with `kind`
/// (`Curl_sendrecv`'s `DEBUGF`).
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
        let gss_read = match c.handshake.as_deref() {
            Some(Handshake::Socks(_)) => socks::timed_out(&mut c, cx),
            _ => None,
        };
        let kind = match c.handshake.as_deref() {
            _ if let Some(failed) = gss_read => failed,
            Some(Handshake::Connect(_)) => trace::fail(
                cx,
                kind,
                format_args!("Proxy CONNECT aborted due to timeout"),
            ),
            Some(Handshake::Socks(_) | Handshake::Haproxy(_) | Handshake::Tls(_)) | None => {
                // Named for the name, while it is not resolved yet.
                let what = match c.lease.reached() {
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
        report_failed(cx, c.lease.partly_made());
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
    let mut entered = false;
    loop {
        if let Some(SetupPoint::Racing { started: false }) = c.lease.reached() {
            https::start(&mut c, &mut run.deadlines, cx);
        }
        let chain = enter_setup(&c, cx, &mut entered);
        let partly = c.lease.partly_made();
        let https = c.https;
        let (next, wake) = connect_once(run, c, cx);
        match next {
            TransferState::Connecting(next) if wake == Wake::Again => c = next,
            TransferState::Done(ref d) => {
                let kind = d.result.expect_err("a setup is done with only as it fails");
                report_failed(cx, partly);
                https::call_ended(https, cx, Err(kind));
                chain_connect_ended(cx, Err(kind));
                if let Some(chain) = chain {
                    // The HTTPS connect filter holds its attempt's
                    // filters apart from the chain once its call is over.
                    let chain = chain.failed();
                    mstate::trace(cx, format_args!("failed to connect {chain}"));
                }
                mstate::trace(
                    cx,
                    format_args!("connect failed -> {}", trace::Code(Err(kind))),
                );
                return (next, wake);
            }
            next => {
                if matches!(next, TransferState::Connecting(_)) {
                    https::call_ended(https, cx, Ok(false));
                    chain_connect_ended(cx, Ok(false));
                }
                return (next, wake);
            }
        }
    }
}

/// A call of the chain's connect ends, up, under way or failed, as the
/// filter at its top, the name's DNS one, traces it (`Curl_conn_connect`).
fn chain_connect_ended<H: Host>(cx: &mut StepCx<'_, H>, ended: Result<bool, ErrorKind>) {
    let (code, done) = match ended {
        Ok(done) => (trace::Code(Ok(())), u8::from(done)),
        Err(kind) => (trace::Code(Err(kind)), 0),
    };
    let dns = Component::Dns;
    trace::of(
        cx,
        dns,
        format_args!("Curl_conn_connect(block=0) -> {code}, done={done}"),
    );
    if ended.is_err() {
        trace::of(
            cx,
            dns,
            format_args!("Curl_conn_connect(), filter returned {code}"),
        );
    }
}

/// What heads the setup's chain above its setup filter.
fn head_of(c: &Connecting) -> Head {
    Head {
        https: c.https.is_some(),
        record: c.https.is_some_and(|h| h.asks()),
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
) -> Option<Chain> {
    let reached = c.lease.reached()?;
    let under_way = c.handshake.as_deref().map(Handshake::filter);
    let head = head_of(c);
    let chain =
        |reached, under_way, installed| Chain::of(&c.route, head, reached, under_way, installed);
    let entry = |cx: &mut StepCx<'_, H>, chain: Chain| {
        mstate::trace(cx, format_args!("cf_setup_connect {chain}"));
    };
    match reached {
        SetupPoint::Resolving => return Some(chain(reached, None, true)),
        SetupPoint::Racing { started: false } => {
            // The happy eyeballs filter is added (`cf_setup_add_ip_happy`).
            entry(cx, chain(reached, None, true));
            let peer = c.route.destination();
            let to = if c.route.proxy.as_ref().is_some_and(|p| p.tunnels()) {
                "proxy"
            } else {
                "origin"
            };
            let (name, port) = (Bytes(peer.name()), peer.port());
            trace::of(
                cx,
                Component::Setup,
                format_args!("happy eyeballing to {to} {name}:{port}"),
            );
            let racing = chain(SetupPoint::Racing { started: true }, None, true);
            entry(cx, racing);
            *entered = true;
            return Some(racing);
        }
        SetupPoint::Racing { started: true } | SetupPoint::Dialed(_) => {}
    }
    if !*entered {
        entry(cx, chain(reached, under_way, true));
        *entered = true;
    }
    let (SetupPoint::Dialed(made), None) = (reached, under_way) else {
        return Some(chain(reached, under_way, true));
    };
    let Some(due) = handshake_due(c, made) else {
        return Some(chain(reached, None, true));
    };
    // The tunnel's filter was added with the HTTPS proxy's TLS below it,
    // and goes on connecting in the same call.
    if let Due::Tunnel = due
        && made.has(Made::PROXY_TLS)
    {
        return Some(chain(reached, Some(Component::HttpProxy), false));
    }
    let filter = match due {
        Due::Socks(_) => {
            let leg = c.route.socks().expect("through a SOCKS proxy");
            let (name, port) = (Bytes(leg.to.name()), leg.to.port());
            trace::of(
                cx,
                Component::Setup,
                format_args!("added SOCKS filter to {name}:{port}"),
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
        Due::Tls(TlsSide::Proxy) if c.route.proxy.as_ref().is_some_and(|p| p.tunnels()) => {
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
    };
    // The tunnel's filter installs its HTTP/1.1 one as it first connects.
    entry(cx, chain(reached, Some(filter), false));
    Some(chain(reached, Some(filter), true))
}

/// One step of the connection's setup within a call: a handshake's, the
/// next handshake started, or a drive of the connect machine.
fn connect_once<H: Host>(
    run: &mut Run,
    mut c: Connecting,
    cx: &mut StepCx<'_, H>,
) -> (TransferState, Wake) {
    match c.handshake.as_deref() {
        Some(Handshake::Socks(_)) => return socks::step(c, cx),
        Some(Handshake::Connect(_)) => return tunnel::step(c, cx),
        Some(Handshake::Haproxy(_)) => return haproxy::step(c, cx),
        Some(&Handshake::Tls(side)) => return tls::step(c, cx, side),
        None => {}
    }
    if let Some(SetupPoint::Dialed(_)) = c.lease.reached() {
        return handshake_next(c, cx);
    }
    let delay = cx.easy().options().limits.eyeballs.0;
    let wildcard = cx.easy().wildcard_resolve;
    let scope = cx.easy().options().address_scope;
    let socket = crate::conn::SocketSetup::of(&cx.easy().options().sockets);
    let haproxy = cx.easy().options().proxy.haproxy;
    #[cfg(test)]
    let layer = cx.easy().options().layer;
    #[cfg(any(test, feature = "test-util"))]
    let linger = cx.rest.linger;
    let max_age = cx.easy().options().limits.reuse.dns_max_age;
    let kept = cx.rest.kept(cx.me, Kind::Names);
    let answered = c.lease.answer().is_some();
    let setup = Setup {
        wildcard,
        max_age,
        delay,
        scope,
        socket,
        haproxy,
        #[cfg(test)]
        layer,
        #[cfg(any(test, feature = "test-util"))]
        linger,
    };
    let connected = c.lease.connect(
        &mut DriveCx {
            step: cx,
            kept: kept.as_ref(),
        },
        setup,
    );
    if answered && c.lease.answer().is_none() {
        // Connected, or failed: the answer is let go.
        cx.rest.net_names(cx.me, kept.as_ref()).1.release();
    }
    // The race is over once an attempt connects, a proxy's or not
    // (`cf_ip_happy_connect`).
    if !matches!(
        connected,
        Ok(Connected::Connecting(
            Progress::Resolved(_)
                | Progress::Trying { .. }
                | Progress::Failed
                | Progress::Waiting { .. }
                | Progress::Resolving { .. }
        ))
    ) {
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
                    let answer = c.lease.answer();
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
            let (remote, _) = c.lease.dialed().ends();
            eyeballs_won(cx, &c.route, &remote);
            (TransferState::Connecting(c), Wake::Again)
        }
        Ok(Connected::Connecting(Progress::Waiting { until })) => {
            waiting(run, cx, until);
            (TransferState::Connecting(c), Wake::Idle)
        }
        // The resolver's answer wakes the multi; a thread it could not
        // start is tried for again at `retry`, or the connect limit's
        // own timer ends the wait (`Curl_async_pollset`).
        Ok(Connected::Connecting(Progress::Resolving { retry })) => {
            match retry {
                Some(at) => {
                    let mut wait = wait_ms(cx.now(), at);
                    let left = run
                        .deadlines
                        .time_left(starts(cx), cx.now(), Phase::Connecting);
                    if let TimeLeft::Remaining(left) = left {
                        wait = wait.min(left);
                    }
                    arm(&mut run.deadlines, cx, TimerKind::AsyncName, wait);
                }
                None => run.deadlines.clear(TimerKind::AsyncName),
            }
            (TransferState::Connecting(c), Wake::Idle)
        }
        Ok(Connected::Established { remote, local, at }) => {
            eyeballs_won(cx, &c.route, &remote);
            up(c, cx, remote, local, at, false)
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
            (TransferState::Connecting(c).fail(kind), Wake::Again)
        }
    }
}

/// Connected to the first hop, or a handshake over it made: the next
/// handshake starts, in cf-setup.c's order, which is decided here alone:
/// the SOCKS proxy's, (the HTTP proxy's TLS, with step 43), the HTTP
/// proxy's tunnel, the PROXY protocol's line, the origin's TLS. With
/// none left, the connection is open.
fn handshake_next<H: Host>(mut c: Connecting, cx: &mut StepCx<'_, H>) -> (TransferState, Wake) {
    let made = c.lease.dialed().made();
    match handshake_due(&c, made) {
        Some(Due::Socks(version)) => return socks::dialed(c, cx, version),
        Some(Due::Tunnel) => return tunnel::dialed(c, cx),
        Some(Due::Preface) => return haproxy::start(c, cx),
        Some(Due::Tls(side)) => return tls::start(c, cx, side),
        None => {}
    }
    let preface = c.lease.sends_preface();
    match c.lease.handshaken() {
        Connected::Established {
            remote, local, at, ..
        } => up(c, cx, remote, local, at, preface),
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
}

/// The handshake to make next over a connection that made `made`, in
/// cf-setup.c's order; none once they are all made.
fn handshake_due(c: &Connecting, made: Made) -> Option<Due> {
    if let Some(version) = c.route.socks().map(|leg| leg.version)
        && !made.has(Made::SOCKS)
    {
        return Some(Due::Socks(version));
    }
    let tunnels = c.route.proxy.as_ref().is_some_and(|p| p.tunnels());
    let proxy_tls = c.route.proxy_tls().is_some() && !made.has(Made::PROXY_TLS);
    if proxy_tls && tunnels {
        return Some(Due::Tls(TlsSide::Proxy));
    }
    if tunnels && !made.has(Made::TUNNEL) {
        return Some(Due::Tunnel);
    }
    if c.lease.sends_preface() && !made.has(Made::PREFACE) {
        return Some(Due::Preface);
    }
    // Requests go whole to the HTTPS proxy: its TLS is the origin's
    // filter, the last but for none.
    if proxy_tls {
        return Some(Due::Tls(TlsSide::Proxy));
    }
    if c.route.tls.is_some() && !made.has(Made::TLS) {
        return Some(Due::Tls(TlsSide::Origin));
    }
    None
}

/// The name `route` connects to first, missing from the cache, is not
/// resolved for IPv6 alone without IPv6 (`can_resolve_dns_queries`).
fn no_ipv6<H: Host>(cx: &mut StepCx<'_, H>, route: &Tcp, proxy: bool) -> ErrorKind {
    trace_lookup(cx, route, Some(Found::Resolved(Asked::Resolver(None))));
    let peer = route.destination();
    let (host, port) = (Bytes(peer.name()), peer.port());
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
    let kind = trace::fail(cx, kind, format_args!("Could not resolve: {host}:{port}"));
    trace::fail(cx, kind, format_args!("Could not resolve: {host}"))
}

/// The debug build failed the resolve of IPv6 addresses alone of the name
/// `route` connects to first, before the cache was looked in
/// (`hostip_resolv`, `CURL_DBG_RESOLV_FAIL_IPV6`).
fn debug_failed_ipv6<H: Host>(cx: &mut StepCx<'_, H>, route: &Tcp, proxy: bool) -> ErrorKind {
    let peer = route.destination();
    let (host, port) = (Bytes(peer.name()), peer.port());
    let queries = queries(peer, route.ip, cx.rest.ipv6_works);
    // The C debug build's line, said here always: only a debug build
    // fails the resolve.
    trace::of(
        cx,
        Component::Dns,
        format_args!("[{queries}] hostip_resolv({host}:{port})"),
    );
    trace::info(cx, format_args!("DEBUG fail ipv6 resolve"));
    let (what, kind) = if proxy {
        ("proxy", ErrorKind::CouldntResolveProxy)
    } else {
        ("host", ErrorKind::CouldntResolveHost)
    };
    let kind = trace::fail(cx, kind, format_args!("Could not resolve {what}: {host}"));
    let kind = trace::fail(cx, kind, format_args!("Could not resolve: {host}:{port}"));
    trace::fail(cx, kind, format_args!("Could not resolve: {host}"))
}

/// The name `route` connects to first was looked up in the cache, as
/// C's `hostip_resolv` and `Curl_dnscache_get` trace it: found, missing
/// (or stale, said first) and so resolved, or `None`, the resolver's no
/// kept from before.
fn trace_lookup<H: Host>(cx: &mut StepCx<'_, H>, route: &Tcp, found: Option<Found>) {
    // The name looked up: the proxy's, or what a connect-to names in the
    // origin's place.
    let peer = route.destination();
    let (name, port, queries) = (
        Bytes(peer.name()),
        peer.port(),
        queries(peer, route.ip, cx.rest.ipv6_works),
    );
    // The C debug build's line.
    #[cfg(feature = "debug-hooks")]
    trace::of(
        cx,
        Component::Dns,
        format_args!("[{queries}] hostip_resolv({name}:{port})"),
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
    trace::of(
        cx,
        Component::Dns,
        format_args!("cache lookup {name}:{port} queries={queries} -> {code} {not}found"),
    );
    if let Some(
        Found::Stale(Asked::Resolver(Some(q))) | Found::Resolved(Asked::Resolver(Some(q))),
    ) = found
    {
        // The threaded resolver's queries, IPv6's queued first
        // (`async_thrdd_query`).
        let xfer = cx.easy().report().transfer_number().map_or(0, |n| n.get());
        let id = q.id.get();
        for (queued, query) in [(q.v6, "AAAA"), (q.v4, "A")] {
            if queued {
                trace::of(
                    cx,
                    Component::Dns,
                    format_args!("queueing query [{xfer}/{id}] {query} {name}:{port}"),
                );
            }
        }
    }
    if found == Some(Found::Cached) {
        trace::info(cx, format_args!("Hostname {name} was found in DNS cache"));
    }
}

/// The name `route` connects to first was resolved, `asked` what
/// answered, to `addrs`, its answer kept; or the resolver failed, having
/// queued what the error says. A shortcut answers at once; the resolver,
/// as the reference build's c-ares does, answers later (`CURLE_AGAIN`),
/// its polls not traced.
fn trace_resolved<H: Host>(
    cx: &mut StepCx<'_, H>,
    route: &Tcp,
    asked: Result<Asked, Option<Queued>>,
    addrs: &[IpAddr],
) {
    let peer = route.destination();
    let (name, port, queries) = (
        Bytes(peer.name()),
        peer.port(),
        queries(peer, route.ip, cx.rest.ipv6_works),
    );
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
    // The threaded resolver's answers, each query's addresses of its
    // family, IPv4's taken first (`async_thrdd_check_done`).
    if let Ok(Asked::Resolver(Some(q))) | Err(Some(q)) = asked {
        for (queued, v6) in [(q.v4, false), (q.v6, true)] {
            if queued {
                let (addrs, c) = (Family(addrs, v6), if v6 { '6' } else { '4' });
                trace::of(
                    cx,
                    dns,
                    format_args!("Host {name}:{port} resolved IPv{c}: {addrs}"),
                );
            }
        }
    }
    if asked.is_err() {
        return;
    }
    if let Ok(Asked::Resolver(_)) = asked {
        trace::of(
            cx,
            dns,
            format_args!("[{queries}] resolve complete for {name}:{port}"),
        );
    }
    trace::of(
        cx,
        dns,
        format_args!("cached entry for {name}:{port} queries={queries}"),
    );
}

/// The setup waits for its sockets, and for the race's next attempt at
/// `until`, if one is left.
fn waiting<H: Host>(run: &mut Run, cx: &mut StepCx<'_, H>, until: Option<Instant>) {
    match until {
        Some(at) => eyeballs_due(run, cx, at),
        // Nothing left to start: C never armed it.
        None => run.deadlines.clear(TimerKind::Eyeballs),
    }
}

/// The race's next attempt is due at `at`: its timer armed for then, or
/// for the end of the time left to connect if that comes first, as C
/// arms it.
fn eyeballs_due<H: Host>(run: &mut Run, cx: &mut StepCx<'_, H>, at: Instant) {
    let now = cx.now();
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
    arm(&mut run.deadlines, cx, TimerKind::Eyeballs, wait);
}

/// The race's attempt to `remote`, the peer `route` connects to first
/// or the proxy a handshake goes through, connected: the race is over,
/// and counted (`cf_ip_happy_connect`).
fn eyeballs_won<H: Host>(cx: &mut StepCx<'_, H>, route: &Tcp, remote: &Remote) {
    let he = Component::HappyEyeballs;
    let (name, ip, port) = (
        Bytes(route.destination().name()),
        remote.shown_ip(),
        remote.port(),
    );
    trace::of(
        cx,
        he,
        format_args!("Connected to {name} ({ip}) port {port}"),
    );
    trace_timer(cx, TimerKind::Eyeballs, format_args!("cleared"));
    cx.report_mut().count_connect();
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
) -> (TransferState, Wake) {
    // What its tunnel negotiated is the connection's from now on.
    *c.lease.get().negotiate_mut() = c.negotiate.take();
    if c.https.is_some() {
        // The winner's chain is asked whether HTTP/2 was agreed
        // (`baller_connected`), from its SETUP filter.
        query_alpn(cx, &c.lease, Component::Setup);
    }
    https::call_ended(c.https, cx, Ok(true));
    chain_connect_ended(cx, Ok(true));
    // Its TLS is up now, and its socket was when it connected
    // (`Curl_pgrsTime` for `TIMER_APPCONNECT` as the SSL filter connects).
    if c.route.tls.is_some() {
        let now = cx.now();
        let marked = cx.report_mut().timings_mut().mark(Timer::AppConnect, now);
        mstate::marked(cx, Timer::AppConnect, marked);
    }
    let marked = cx.report_mut().timings_mut().mark(Timer::Connect, at);
    mstate::marked(cx, Timer::Connect, marked);
    // `CURL_CONN_HOST_DISPNAME`.
    let host = Bytes(c.route.destination().shown());
    let (lip, lport) = local.map_or((None, 0), |l| (Some(l.ip()), l.port()));
    let lip = Ip(lip);
    trace::info(
        cx,
        format_args!(
            "Established connection to {host} ({} port {}) from {lip} port {lport} ",
            remote.shown_ip(),
            remote.port()
        ),
    );
    cx.report_mut().set_primary(Ends { remote, local });
    // The setup filters go once the chain is connected
    // (`Curl_conn_remove_setup_filters`).
    let connected = Chain::connected(&c.route, head_of(&c), preface);
    mstate::trace(cx, format_args!("connected {connected}"));
    for filter in connected.going() {
        trace::of(cx, filter, format_args!("removing connected setup filter"));
        trace::of(cx, filter, format_args!("destroy"));
    }
    let reduced = connected.reduced();
    mstate::trace(cx, format_args!("reduced to {reduced}"));
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
    let failure = match e {
        ConnectError::OutOfMemory => return ErrorKind::OutOfMemory,
        ConnectError::Unresolved(why) => {
            match why {
                Unresolved::NoIpv6 => return no_ipv6(cx, route, proxy.is_some()),
                Unresolved::DebugFailIpv6 => return debug_failed_ipv6(cx, route, proxy.is_some()),
                Unresolved::UnixPathTooLong => {
                    // `resolv_unix`, then the name's filter, which says
                    // the path alone.
                    let path = Bytes(first.name());
                    let kind = ErrorKind::CouldntResolveHost;
                    let kind = trace::fail(
                        cx,
                        kind,
                        format_args!("Unix socket path too long: '{path}'"),
                    );
                    trace::info(cx, format_args!("Could not resolve: {path}"));
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
            let (host, port) = (Bytes(first.name()), first.port());
            let (what, kind) = match proxy {
                Some(_) => ("proxy", ErrorKind::CouldntResolveProxy),
                None => ("host", ErrorKind::CouldntResolveHost),
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
                        Some(reason) => trace::fail(
                            cx,
                            kind,
                            format_args!("Could not resolve {what}: {host} ({reason})"),
                        ),
                        None => {
                            trace::fail(cx, kind, format_args!("Could not resolve {what}: {host}"))
                        }
                    };
                    trace::fail(cx, kind, format_args!("Could not resolve {what}: {host}"))
                }
                _ => trace::fail(cx, kind, format_args!("Could not resolve {what}: {host}")),
            };
            // What the resolver said no to is kept as said
            // (`Curl_dnscache_add_negative`).
            if let Unresolved::Resolver {
                why: ResolveFailure::NotFound | ResolveFailure::NoData,
                ..
            } = why
            {
                let queries = queries(first, route.ip, cx.rest.ipv6_works);
                trace::of(
                    cx,
                    Component::Dns,
                    format_args!("cache negative name resolve for {host}:{port} type={queries}"),
                );
            }
            trace::info(cx, format_args!("Could not resolve: {host}:{port}"));
            if why == Unresolved::Negative {
                trace::info(cx, format_args!("Could not resolve: {host}"));
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
    let (host, port) = (Bytes(origin.name()), origin.port());
    // A peer that is neither the origin nor the proxy named is shown.
    let via = Via(Some(first).filter(|&f| f != origin && Some(f) != proxy));
    let over = OverProxy(proxy);
    let ms = cx.easy().report().timings().since_single_ms(cx.rest.now);
    // The last attempt's failure says what the setup's is.
    let why = failure.message();
    trace::fail(
        cx,
        failure,
        format_args!("Failed to connect to {host}:{port}{via} {over}after {ms} ms: {why}"),
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
            Some(peer) if peer.is_unix() => write!(f, " over unix://{}", Bytes(peer.name())),
            Some(peer) => write!(f, " via {}:{}", Bytes(peer.name()), peer.port()),
            None => Ok(()),
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
    run.allow_port = true;
    run.http = Inherited::default();
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
    crate::proto::http::hsts::load(cx)?;
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
    if let Some(port) = cx.easy().options().port.filter(|_| run.allow_port) {
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
        run.allow_port = false;
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
    let shown = Bytes(&text);
    trace::info(
        cx,
        format_args!("Issue another request to this URL: '{shown}'"),
    );
    let switched = proto.redirected(cx, code, &mut run.method, &mut run.http);
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
    // As for a redirect, which never switches to GET here. A retry always
    // rewinds (`Curl_retry_request`).
    client_start(cx);
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
    start_leg(run, cx, url)
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
) -> Result<bool, ErrorKind> {
    let reused = x.proto.retryable() && x.lease.conn().reused();
    // A stream HTTP/2 refused is safe to make again, on any connection,
    // if nothing came on it.
    let refused = x.proto.take_refused() && x.proto.retryable();
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
/// `url`, then the protocol connects over it.
fn start_leg<H: Host>(run: &mut Run, cx: &mut StepCx<'_, H>, mut url: Url) -> TransferState {
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
    upload::trace_reset(cx, false);
    cx.mark_now(Timer::PostQueue);
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
    let redirected = cx.report_mut().redirects() > 0;
    let refused = !cx.easy().options().schemes.permit(&scheme, redirected);
    // C reads a `.netrc` before it checks the protocol; an HTTP request
    // reads it as it is made, any other URL here.
    let http = match &*scheme {
        b"http" => true,
        b"https" => cx.easy().libraries().tls.is_some(),
        _ => false,
    };
    if (refused || !http)
        && let Err(kind) = crate::proto::netrc_before_protocol(&url, cx)
    {
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
    let target = proto.network(
        &url,
        cx.easy().options().address_scope,
        cx.easy().libraries().idn,
    );
    let target = match target {
        Ok(Some(target)) => target,
        Ok(None) => {
            let lease = match acquire(cx, &proto, Route::Local) {
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
    let mut alt_used = false;
    let via = match unix {
        Some(peer) => Some(peer),
        None => match connect_to(cx, &origin) {
            Ok(Some(via)) => Some(via),
            // No connect-to entry: an alternative service, then.
            Ok(None) => match alt_svc(cx, &origin, &scheme) {
                Ok(via) => {
                    alt_used = via.is_some();
                    via
                }
                Err(e) => return TransferState::Init.fail(e),
            },
            Err(e) => return TransferState::Init.fail(e),
        },
    };
    let secured = proto.secured();
    let proxy = if over_unix {
        None
    } else {
        match choose_proxy(cx, &origin, &scheme, via.is_some() || secured) {
            Ok(proxy) => proxy,
            Err(e) => return TransferState::Init.fail(e),
        }
    };
    // A request a proxy sends on names the whole URL, and the connection
    // is the proxy's (`origin_is_proxy`).
    let mut proto = proto;
    if alt_used {
        let via = via.as_deref().expect("an alternative is the peer");
        if let Err(OutOfMemory) = proto.alt_used(via) {
            return TransferState::Init.fail(ErrorKind::OutOfMemory);
        }
    }
    let origin = match &proxy {
        Some(p) if p.forward => {
            if let Err(e) = proto.forward(&url) {
                return TransferState::Init.fail(e);
            }
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
    // The local end each socket binds, which a connection must share to
    // serve it (`conn->interface_opts`, `localport`, `localportrange`).
    let bind = &cx.easy().options().sockets.local;
    let local = match bind.binds().then(|| bind.try_clone()) {
        None => None,
        Some(Ok(bind)) => match TryArc::try_new(bind) {
            Ok(bind) => Some(bind),
            Err(OutOfMemory) => return TransferState::Init.fail(ErrorKind::OutOfMemory),
        },
        Some(Err(OutOfMemory)) => return TransferState::Init.fail(ErrorKind::OutOfMemory),
    };
    let route = Tcp {
        origin,
        via,
        ip: cx.easy().options().ip_version,
        proxy,
        tls,
        local,
        // Compared for any protocol, as C compares it (`url_match_auth`).
        delegation: cx.easy().options().login.delegation,
    };
    setup(cx, Plan { proto, route })
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
    // tunnel, or reaches the origin through another peer, or is secured;
    // HTTP's schemes are the only ones here.
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
    let acquired = acquire(cx, &plan.proto, Route::Tcp(plan.route.clone()));
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
    let Plan { proto, route } = plan;
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
        mstate::trace(cx, format_args!("Curl_conn_setup() -> 0"));
    }
    TransferState::Connecting(Connecting {
        lease,
        proto,
        route,
        handshake: None,
        https,
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
            let text = Bytes(text);
            (kind, trace::reason(format_args!("{why} in '{text}'")))
        }
    };
    Err(trace::fail_for(cx, kind, reason))
}

/// The peer an alternative service sends a connection for `origin` to, if
/// the cache is on and knows one other than the origin itself, for an
/// `https` URL, or any in a debug build told `CURL_ALTSVC_HTTP`
/// (`url_set_conn_peer`). Only HTTP/1 alternatives are taken, which is
/// all this build speaks, and none for a request made in HTTP/1.0.
fn alt_svc<H: Host>(
    cx: &mut StepCx<'_, H>,
    origin: &Peer,
    scheme: &[u8],
) -> Result<Option<TryArc<Peer>>, ErrorKind> {
    let Some(alt_svc) = cx.easy().alt_svc() else {
        return Ok(None);
    };
    let secured = scheme == b"https";
    #[cfg(feature = "debug-hooks")]
    let secured = secured || curl_os::env::is_set(b"CURL_ALTSVC_HTTP");
    if !secured || cx.easy().options().http.version == crate::options::HttpVersion::Http10 {
        return Ok(None);
    }
    let allowed = crate::altsvc::Versions {
        h1: alt_svc.ctrl().versions.h1,
        h2: false,
        h3: false,
    };
    let now = crate::date::cache_now(cx.unix_time());
    let alt_svc = cx.easy_mut().alt_svc_mut().expect("on, as above");
    let src = crate::altsvc::Alpn::H1;
    let Some(found) = alt_svc.lookup((origin.name(), origin.port(), src), allowed, now) else {
        return Ok(None);
    };
    // The same host and port by another version would change only the
    // version wanted, and there is none other.
    if found.same {
        return Ok(None);
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
    trace::info(
        cx,
        format_args!(
            "Alt-svc connecting from [{}]{}:{} to [{}]{}:{}",
            src.name(),
            Bytes(origin.name()),
            origin.port(),
            dst_alpn.name(),
            Bytes(via.name()),
            via.port()
        ),
    );
    TryArc::try_new(via).map(Some).map_err(oom)
}

/// A connection for the transfer making `proto`, and the trace of what
/// the search for one did.
/// `last` is the transfer's last connection, tried first and then
/// replaced by the one it gets.
fn acquire<H: Host>(
    cx: &mut StepCx<'_, H>,
    proto: &ProtoState,
    route: Route,
) -> Result<Acquired, OutOfMemory> {
    let auth = &cx.easy().auth;
    let wants = match (proto, &route) {
        (ProtoState::Http(request), Route::Tcp(tcp)) => {
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
    let versions = proto.http_versions(cx.easy().options());
    // An HTTP transfer that may speak HTTP/2 shares a connection that
    // multiplexes, as the multi lets it (`xfer_may_multiplex`).
    let http = matches!(proto, ProtoState::Http(_));
    let multiplex = (cx.rest.tell.limits.multiplex && http && versions.h2)
        .then_some(cx.rest.tell.limits.max_streams);
    let pipewait = cx.easy().options().http.pipewait;
    let found = if pool::searches(&route, rules) {
        cx.rest.pool_search(cx.me, &home, |pool, exits, here| {
            pool.find(
                here,
                pool::Wanted {
                    route: &route,
                    auth: wants,
                    last,
                    versions,
                    multiplex,
                    pipewait,
                },
                rules,
                exits,
                now,
                &mut notes,
            )
        })?
    } else {
        pool::Found::Nothing
    };
    let acquired = match found {
        pool::Found::Lease(lease) => Acquired::Reused(lease),
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
                pool.add(here, route, closer, settings, add, exits, now)
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
            PoolNote::Closed(n) => trace::info(cx, format_args!("shutting down connection {n}")),
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
