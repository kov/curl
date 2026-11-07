//! The multi: transfers driven together, as libcurl's multi handle drives
//! them (`lib/multi.c`).
//!
//! A multi owns its transfers, their connections and its clock. The
//! application adds an `Easy`, drives the multi with `perform` or
//! `socket_action`, reads completions with `info_read`, and gets the
//! `Easy` back with `remove`. It learns when to drive the multi next
//! through the timer events of its `MultiEvents`.

#[cfg(debug_assertions)]
mod check;
pub(crate) mod cx;
pub(crate) mod dns;
pub(crate) mod doh;
pub(crate) mod mstate;
mod notify;
mod pending;
pub(crate) mod push;
pub mod raw;
mod sched;
mod sockets;
mod ssls;
pub(crate) mod state;
pub(crate) mod timers;
mod wait;

use std::num::NonZeroU32;
use std::time::Duration;

use curl_alloc::{OutOfMemory, TryArc};

use crate::conn::io::{Events, Net, Socket, SocketKey, Waker};
use crate::conn::shutdown::{Linger, ShutdownSet, WithSet};
use crate::conn::{AddLimits, Caches, Pool};
use crate::conn::{ConnId, Home};
use crate::deliver::{Pause, RecvPause};
use crate::easy::{Easy, EasyView};
use crate::error::{ErrorKind, MultiErrorKind};
use crate::handler::Handler;
use crate::id::{Arena, ArenaPolicy, Key};
use crate::progress::Speedometer;
use crate::progress::rate::{RateLimits, Way};
use crate::share::{Kind, Share, ShareInUse, ShareLock, watched};
#[cfg(any(test, feature = "test-util"))]
use crate::time::Clock;
use crate::time::Instant;
use crate::tls::{TlsNative, TlsShared};
use crate::upload::Readers;

pub use crate::deliver::PauseRequest;
use cx::{Announcing, EngineRest, Telling};
pub use cx::{EventCx, NotifyCx, TransferCx};
pub(crate) use cx::{LoneCalls, TransferCalls};
pub use notify::{Notification, NotifyKind};
pub use push::{PushFields, PushOffer, Pushed};
pub use sched::{Census, Counts};
pub use sockets::{SocketFor, SocketWhat, UnknownSocket};
pub use ssls::{ExportDone, ExportFailed, Exporting, SessionsOut};
pub use timers::TimerChange;
#[cfg(any(test, feature = "test-util"))]
pub use wait::drive_within;
pub use wait::{EventTable, drive_by_events_with};
pub use wait::{WaitMode, drive_by_events, drive_to_completion};

use notify::NotifyQueue;
use pending::PendingQueue;
use sched::{RowSet, Tally};
use sockets::{SocketOwner, SocketTable, Wants};
use state::{PollsetTrace, Run, StepCx, TransferState, Wake};
use timers::{Due, TimerAnnounce, TimerKind, TimerQueue};

/// The application's types a multi carries: a value per transfer, handed
/// back with its messages and on removal, and a value per socket it
/// watches, handed back to its socket callback (`curl_multi_assign`);
/// and what the multi asks of a transfer's value.
pub trait Host {
    type Transfer;
    type Socket: Copy;

    /// The URL the application keeps for `transfer` elsewhere than its
    /// options, asked for as each of its transfers starts and before
    /// `Options::shared_url` (C's `set.uh`, read by `Curl_pretransfer`).
    /// The share lasts the read alone: the transfer keeps a copy.
    fn start_url(transfer: &Self::Transfer) -> Option<crate::url::SharedUrl> {
        let _ = transfer;
        None
    }
}

/// A multi that carries nothing for the application.
#[derive(Debug)]
pub struct NoHost;

impl Host for NoHost {
    type Transfer = ();
    type Socket = ();
}

/// What `TransferId`s name.
#[derive(Debug)]
pub enum Transfer {}

/// A transfer in a multi; stale once it is removed.
pub type TransferId = Key<Transfer>;

/// A transfer out of its slot: its handle, who owned it, and what its
/// timer call came to.
type TakenOut<H> = (Box<Easy>, Owner<H>, Result<(), MultiErrorKind>);

/// Who a transfer is for: the application, which gave a value of its own
/// with it, or another transfer it does work for, which the application
/// never added nor removes (`state.internal`, `master_mid`). A host that
/// names its handles to its callbacks has one for it too, which the multi
/// gives back through `MultiEvents::internal_gone`.
pub(crate) enum Owner<H: Host> {
    App(H::Transfer),
    Internal {
        master: TransferId,
        host: Option<H::Transfer>,
        probe: doh::Probe,
    },
}

impl<H: Host> Owner<H> {
    /// The value callbacks name the transfer by, if it has one.
    fn host(&self) -> Option<&H::Transfer> {
        match self {
            Owner::App(host) => Some(host),
            Owner::Internal { host, .. } => host.as_ref(),
        }
    }

    fn is_internal(&self) -> bool {
        matches!(self, Owner::Internal { .. })
    }
}

/// An application callback's request to stop: the multi fails every
/// transfer and accepts no more until it is empty.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Abort;

/// What the multi tells the application while it runs.
pub trait MultiEvents<H: Host> {
    /// The multi wants to be driven after this long, or no longer
    /// (`CURLMOPT_TIMERFUNCTION`). Called only on a change.
    fn timer(&mut self, cx: &mut EventCx<'_, H>, change: TimerChange) -> Result<(), Abort> {
        let _ = (cx, change);
        Ok(())
    }

    /// Something enabled with `set_notify` happened
    /// (`CURLMOPT_NOTIFYFUNCTION`). Called at the end of `perform` and
    /// `socket_action`, in the order the notifications were queued.
    fn notify(&mut self, cx: &mut NotifyCx<'_, H>, n: Notification) {
        let _ = (cx, n);
    }

    /// Transfer `id`, owned by `owner`, was just added, before the timer
    /// hears of it: from here the host may name it, as a timer callback
    /// inside the add may. Only of the application's: one of the multi's
    /// own is named to the host only by the value `internal` made for it.
    fn added(&mut self, id: TransferId, owner: &H::Transfer) {
        let _ = (id, owner);
    }

    /// The multi makes `easy`, a transfer of its own doing work for
    /// `master` (a DoH probe): the host's value for it, if it names its
    /// transfers to its callbacks, with `easy` back as the transfer is to
    /// run. Called inside the master's step.
    fn internal(
        &mut self,
        cx: &mut EventCx<'_, H>,
        master: TransferId,
        easy: Box<Easy>,
    ) -> Result<(Box<Easy>, Option<H::Transfer>), OutOfMemory> {
        let _ = (cx, master);
        Ok((easy, None))
    }

    /// An internal transfer went, or could not be added: what the host made
    /// for it is the host's to dispose of (`Curl_close`).
    fn internal_gone(&mut self, easy: Box<Easy>, host: H::Transfer) {
        let _ = (easy, host);
    }

    /// Whether `timer` is wanted. Without it the multi keeps no record of
    /// what it announced, as C without a timer callback.
    fn wants_timer(&self) -> bool {
        false
    }

    /// A server offers to push a response beside one of a transfer's
    /// (`CURLMOPT_PUSHFUNCTION`): `easy` is made for it, its URL set, for
    /// the application to set more of and take, or refuse. Called inside
    /// the parent's step, as the offer is read; `cx` reaches the parent and
    /// the rest of the multi as a socket callback's does.
    fn push(
        &mut self,
        cx: &mut EventCx<'_, H>,
        offer: &PushOffer<'_>,
        easy: Box<Easy>,
    ) -> Pushed<H> {
        let _ = (cx, offer, easy);
        Pushed::Denied
    }

    /// Whether `push` is wanted: without it, servers are told not to push
    /// (`SETTINGS_ENABLE_PUSH`).
    fn wants_push(&self) -> bool {
        false
    }

    /// A push `push` took could not be added after all, or was added and
    /// could not start, the multi short of memory: what was made for it
    /// is the host's to dispose of, as C closes the handle
    /// (`discard_newhandle`). One added, which `added` told of, is out of
    /// the multi by now, taken out as the step that added it ended, with
    /// no message.
    fn unpushed(&mut self, easy: Box<Easy>, owner: H::Transfer) {
        let _ = (easy, owner);
    }

    /// Watch socket `s` for `what` for `who`, or stop
    /// (`CURLMOPT_SOCKETFUNCTION`). Called on a change only, after a
    /// transfer runs in `socket_action`, inside `remove` and `pause`, as a
    /// connection starts shutting down, and before a socket waited on
    /// closes. `assigned` is the application's value for the socket.
    fn socket(
        &mut self,
        cx: &mut EventCx<'_, H>,
        who: SocketFor,
        s: SocketKey,
        what: SocketWhat,
        assigned: Option<H::Socket>,
    ) -> Result<(), Abort> {
        let _ = (cx, who, s, what, assigned);
        Ok(())
    }

    /// Whether `socket` is wanted. Without it the multi keeps no record of
    /// the sockets, as C without a socket callback.
    fn wants_sockets(&self) -> bool {
        false
    }
}

/// Events nobody listens to.
#[derive(Debug, Default)]
pub struct NoEvents;

impl<H: Host> MultiEvents<H> for NoEvents {}

/// How a multi is made: its network, the ids it hands out, and the waker
/// other threads use to interrupt its waits. Without a waker, nothing can
/// (C always makes one; the shim does too). It reads the system's clock,
/// as C does; only a test gives it another.
pub struct Env {
    /// The multi's time, a test's own. Every multi using one share reads
    /// one clock, clones of one `ManualClock` say, as the share's names
    /// and connections carry their instants: the debug build panics at a
    /// share's use under a second.
    #[cfg(any(test, feature = "test-util"))]
    pub clock: Box<dyn Clock>,
    pub net: Box<dyn Net + Send>,
    pub arena: ArenaPolicy,
    pub waker: Option<TryArc<Waker>>,
}

impl Env {
    /// A multi on the system's clock, with `net`, `arena` and `waker`.
    pub fn new(net: Box<dyn Net + Send>, arena: ArenaPolicy, waker: Option<TryArc<Waker>>) -> Env {
        Env {
            #[cfg(any(test, feature = "test-util"))]
            clock: curl_alloc::try_box(crate::time::SystemClock::new())
                .expect("a clock that holds nothing takes no memory"),
            net,
            arena,
            waker,
        }
    }
}

/// The multi's state after a callback's abort.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Life {
    Alive,
    /// Every transfer fails; nothing is added until the multi is empty.
    Dead,
}

struct Slot<H: Host> {
    owner: Owner<H>,
    /// In memory of its own, which the handle's owner hands in and takes
    /// back: the transfer's options and report do not move, nor are they
    /// kept twice.
    easy: Box<Easy>,
    /// Reachable while the run is out, for the transfer's own handlers.
    pause: Pause,
    /// The transfer's own handler changed its pause while its run was out:
    /// whether that blocks it is judged once the run is back, against the
    /// ways its request then moves bytes.
    judge_pause: bool,
    /// Beside the pause, which starts it over.
    speedometer: Speedometer,
    /// The speed limits' buckets, which the pause stops and starts over.
    rate: RateLimits,
    /// Out only while the transfer is being stepped.
    run: Option<Run>,
    /// Where it is in C's states, for the trace.
    mstate: mstate::MState,
    /// The readers C would stack for the request's body, for the trace of
    /// a lift of the pause one of them asked for.
    readers: Option<Readers>,
    /// The sockets its libraries closed, until they are told; made as its
    /// first library's resolve starts.
    closed: Option<crate::conn::io::SocketsClosed>,
    /// A pushed transfer that could not start: taken out, and its handle
    /// given back to the host to close, as the step that added it ends
    /// (`discard_newhandle`).
    discard: bool,
    /// Which of its setups' DNS filters hold an entry of the cache, let
    /// go of as each filter goes, all of them by the transfer's end.
    holds: crate::conn::Holds,
}

/// An `Easy` the multi did not take, and why.
#[derive(Debug)]
pub struct AddError {
    pub kind: MultiErrorKind,
    pub easy: Box<Easy>,
}

/// A transfer taken out of the multi.
#[derive(Debug)]
pub struct Removed<H: Host> {
    pub easy: Box<Easy>,
    pub owner: H::Transfer,
    /// The timer callback's verdict on the change; an abort leaves the
    /// multi dead, but the transfer is out.
    pub status: Result<(), MultiErrorKind>,
}

/// A completed transfer's result (`CURLMSG_DONE`).
#[derive(Debug)]
pub struct Message<'a, H: Host> {
    pub id: TransferId,
    pub owner: &'a H::Transfer,
    pub result: Result<(), ErrorKind>,
    /// Messages still unread after this one.
    pub remaining: u32,
}

/// What wakes `socket_action`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SocketEvent {
    /// The timer the multi asked for ran out (`CURL_SOCKET_TIMEOUT`).
    Timeout,
    /// Something happened on a socket the multi asked to watch; one it
    /// does not know runs only what is due.
    Socket(SocketKey),
}

/// The multi's limits on its connections: none set by default, and HTTP/2
/// multiplexing allowed with C's 100 streams.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ConnLimits {
    /// How many it keeps once one goes idle (`CURLMOPT_MAXCONNECTS`):
    /// past it, the one longest unused is closed. None keeps twice the
    /// transfers added, and closes only a connection unused for a
    /// second.
    pub max_connects: Option<NonZeroU32>,
    /// How many may be open to one host at once
    /// (`CURLMOPT_MAX_HOST_CONNECTIONS`): a transfer that would pass it
    /// waits for one to close.
    pub max_host: Option<NonZeroU32>,
    /// How many may be open at once (`CURLMOPT_MAX_TOTAL_CONNECTIONS`),
    /// likewise.
    pub max_total: Option<NonZeroU32>,
    /// Transfers may share an HTTP/2 connection (`CURLMOPT_PIPELINING`'s
    /// `CURLPIPE_MULTIPLEX`, C's default).
    pub multiplex: bool,
    /// The streams a server may open at once on a connection, as the
    /// client's SETTINGS say (`CURLMOPT_MAX_CONCURRENT_STREAMS`).
    pub max_streams: NonZeroU32,
}

impl Default for ConnLimits {
    fn default() -> Self {
        ConnLimits {
            max_connects: None,
            max_host: None,
            max_total: None,
            multiplex: true,
            max_streams: NonZeroU32::new(100).expect("not zero"),
        }
    }
}

impl ConnLimits {
    pub(crate) fn add(&self) -> AddLimits {
        AddLimits {
            max_host: self.max_host,
            max_total: self.max_total,
        }
    }
}

/// The transfers, each in a row as C's ids number them. A row holds its
/// slot boxed, as C's holds a pointer: a table's empty rows cost little,
/// and C's limits on a transfer's memory count them.
type Slots<H> = Arena<Box<Slot<H>>, Transfer>;

impl<H: Host> Slots<H> {
    /// Transfer `id`'s slot, if it is one the application may name: every
    /// call the multi and its contexts take a `TransferId` in comes through
    /// here, and finds none for a transfer of the multi's own, as C refuses
    /// a `state.internal` handle (`Curl_eapi_enter`). Only what callbacks
    /// are handed to name a transfer by, its owner, is answered for one.
    fn app(&self, id: TransferId) -> Option<&Slot<H>> {
        self.get(id)
            .filter(|s| !s.owner.is_internal())
            .map(|s| &**s)
    }

    /// The same, to change.
    fn app_mut(&mut self, id: TransferId) -> Option<&mut Slot<H>> {
        self.get_mut(id)
            .filter(|s| !s.owner.is_internal())
            .map(|s| &mut **s)
    }
}

pub struct Multi<H: Host = NoHost> {
    slots: Slots<H>,
    dirty: RowSet,
    timers: TimerQueue<Transfer>,
    announce: TimerAnnounce,
    notify: NotifyQueue,
    /// Notifications are being delivered.
    delivering: bool,
    caches: Caches,
    /// What the TLS library keeps across the connections made here,
    /// made with the first TLS session; the multi's own, never a share's,
    /// as C keeps it.
    tls: Option<TlsShared>,
    /// The room QUIC's datagrams are received in, lent to one transfer's
    /// step at a time (`xfer_sockbuf`): empty until one asks.
    sockbuf: crate::conn::quic::RecvRoom,
    /// The connections shutting down, whichever pool they left.
    shutdowns: ShutdownSet,
    limits: ConnLimits,
    /// The transfers waiting for room for a connection, and the plan
    /// each looks again with.
    pending: PendingQueue,
    sockets: SocketTable<H::Socket>,
    clock: crate::time::SharedClock,
    net: Box<dyn Net + Send>,
    /// IPv6 works here, as the network said once as the multi was made
    /// (`Curl_probeipv6`, `multi->ipv6_works`): a property of the system
    /// its transfers run on, kept by the root they reach it through.
    ipv6_works: bool,
    /// Every resolve of IPv6 addresses alone fails, as the debug build's
    /// `CURL_DBG_RESOLV_FAIL_IPV6` asks (`hostip_resolv`): read as the
    /// multi is made, as the tests set it before the process starts.
    fail_ipv6: bool,
    waker: Option<TryArc<Waker>>,
    /// The multi is one handle's own, which `perform` runs it in (C's
    /// `multi_easy`).
    handle_own: bool,
    /// Its connections were closed for good (`curl_multi_cleanup`): the
    /// drop after the application's cleanup has nothing left to close,
    /// and says nothing.
    closed: bool,
    /// The transfers alive, and the resolver's wake listened on while
    /// any is.
    alive: cx::Alive,
    counts: Tally,
    /// Whether a resolve over DoH dropped since the multi last looked for
    /// probes to take out.
    reaping: doh::Reaping,
    /// A step marked a pushed transfer that could not start, to be taken
    /// out as the step ends; never set between calls.
    discards: bool,
    life: Life,
    /// A transfer was told the library is a debug build.
    #[cfg(feature = "debug-hooks")]
    warned: bool,
    /// The debug build's `CURL_DEBUG` was set as the multi was made: its
    /// internal trace is on, with the components of the first transfer
    /// added, the process's.
    #[cfg(feature = "debug-hooks")]
    traces_internally: bool,
    /// The tests' layer each connection set up from here is given.
    #[cfg(any(test, feature = "test-util"))]
    linger: Option<crate::conn::layer::Linger>,
    /// Winsock, started for as long as the multi's sockets live: last, so
    /// that it ends after them. Windows counts the starts, so the
    /// multi's own holds it up whoever else started it; one the system
    /// refused is none, and each socket then fails to open, saying so.
    _winsock: Option<curl_os::net::Winsock>,
}

/// The limit `CURL_DBG_MAX_TOTAL_CONNECTIONS` gives: its leading digits,
/// none past 32 bits or without any (`curlx_str_number` to
/// `UINT32_MAX`); 0 is no limit.
#[cfg_attr(not(feature = "debug-hooks"), allow(dead_code))]
fn debug_max_total(given: &[u8]) -> Option<u32> {
    let digits = given.iter().take_while(|b| b.is_ascii_digit());
    let mut n: u32 = 0;
    let mut any = false;
    for &d in digits {
        n = n.checked_mul(10)?.checked_add(u32::from(d - b'0'))?;
        any = true;
    }
    any.then_some(n)
}

impl<H: Host> Multi<H> {
    /// A multi over `env`. On Windows its network and waker were made
    /// while Winsock was started by whoever made them; the multi holds a
    /// start of its own from here.
    pub fn new(env: Env) -> Result<Self, OutOfMemory> {
        let winsock = curl_os::net::Winsock::start().ok();
        let slots = Arena::new(env.arena)?;
        let caches = Caches::new()?;
        // As C's multi is made, after its waker (`Curl_multi_handle`).
        let mut net = env.net;
        let ipv6_works = net.probe_ipv6()?;
        let fail_ipv6 =
            cfg!(feature = "debug-hooks") && curl_os::env::is_set(b"CURL_DBG_RESOLV_FAIL_IPV6");
        // The debug build's limit on connections, every multi's as it is
        // made (`CURL_DBG_MAX_TOTAL_CONNECTIONS`).
        #[cfg_attr(not(feature = "debug-hooks"), allow(unused_mut))]
        let mut limits = ConnLimits::default();
        #[cfg(feature = "debug-hooks")]
        {
            let mut buf = [0u8; 24];
            if let Some(given) = curl_os::env::var_into(b"CURL_DBG_MAX_TOTAL_CONNECTIONS", &mut buf)
                && let Some(max) = debug_max_total(given)
            {
                limits.max_total = NonZeroU32::new(max);
            }
        }
        let mut alive = cx::Alive::default();
        net.with_resolver(&mut |r| {
            alive.waker = r.waker();
            alive.pool = r.pool();
        });
        #[cfg(any(test, feature = "test-util"))]
        let clock = crate::time::SharedClock::new(env.clock)?;
        #[cfg(not(any(test, feature = "test-util")))]
        let clock = crate::time::SharedClock::system();
        Ok(Multi {
            slots,
            dirty: RowSet::default(),
            timers: TimerQueue::new(),
            announce: TimerAnnounce::default(),
            notify: NotifyQueue::default(),
            delivering: false,
            caches,
            tls: None,
            sockbuf: crate::conn::quic::RecvRoom::Unmade,
            shutdowns: ShutdownSet::new(clock.clone()),
            limits,
            pending: PendingQueue::default(),
            sockets: SocketTable::new(),
            clock,
            net,
            ipv6_works,
            fail_ipv6,
            waker: env.waker,
            handle_own: false,
            closed: false,
            alive,
            counts: Tally::default(),
            reaping: doh::Reaping::default(),
            discards: false,
            life: Life::Alive,
            #[cfg(feature = "debug-hooks")]
            warned: false,
            // C's internal handle is verbose under it (`Curl_multi_handle`).
            #[cfg(feature = "debug-hooks")]
            traces_internally: curl_os::env::is_set(b"CURL_DEBUG"),
            #[cfg(any(test, feature = "test-util"))]
            linger: None,
            _winsock: winsock,
        })
    }

    /// Trace the work done for no transfer on standard error, `components`
    /// saying which lines, as C's debug build traces its internal handle
    /// under `CURL_DEBUG`.
    pub fn trace_internally(&mut self, components: crate::components::Components) {
        self.shutdowns
            .trace_internally(crate::trace::Internal::new(components));
    }

    /// As `trace_internally`, to `sink`.
    #[cfg(any(test, feature = "test-util"))]
    pub fn trace_internally_to(
        &mut self,
        components: crate::components::Components,
        sink: crate::handler::Handler<dyn crate::handler::TextSink>,
    ) {
        self.shutdowns
            .trace_internally(crate::trace::Internal::to(components, sink));
    }

    /// Keep the TLS sessions of `peers` peers, as many as C's
    /// `curl_easy_perform` keeps for its own multi, in place of the 25 a
    /// multi keeps (`Curl_multi_handle`'s `sesssize`). Only while none is
    /// kept.
    pub(crate) fn keep_tls_sessions_of(&mut self, peers: usize) {
        self.caches.sessions = crate::tls::SessionCache::new(peers);
    }

    /// Each connection set up from now on gets a layer whose shutdown
    /// waits as `how` says, for the tests of the connections shutting
    /// down; none with `None`.
    #[cfg(any(test, feature = "test-util"))]
    pub fn linger_connections(&mut self, how: Option<crate::conn::Linger>) {
        self.linger = how;
    }

    /// The most threads the multi's resolver answers from, for a resolver
    /// that answers from a pool of them (`CURLMOPT_RESOLVE_THREADS_MAX`).
    pub fn set_resolve_threads_max(&mut self, max: NonZeroU32) {
        self.alive.set_resolve_threads_max(max);
    }

    /// Make the multi one handle's own, which `perform` runs it in (C's
    /// `multi_easy`): a handle that only connected keeps its connection as
    /// it comes out, and its next transfer here closes it if the handle
    /// used it.
    pub fn make_handle_own(&mut self) {
        self.handle_own = true;
    }

    /// Close the connection `conn` transfer `id`'s handle had reserved,
    /// if its pool still has it, and say so (`Curl_conn_close`).
    fn close_reserved(&mut self, id: TransferId, conn: ConnId, ev: &mut dyn MultiEvents<H>) {
        let now = self.clock.now();
        let mut cx = StepCx::new(id, self.rest(now, ev));
        let home = match cx.rest.kept(cx.me, Kind::Connections) {
            Some(kept) => Home::Share(kept.share),
            None => Home::Multi,
        };
        let closed = cx.rest.pool_section(cx.me, &home, |pool, exits, _| {
            pool.close_reserved(conn, exits, now)
        });
        if let Some(n) = closed {
            crate::trace::info(&mut cx, format_args!("closing connection {n}"));
        }
    }

    /// Whether dropping the multi leaves its resolver's threads running
    /// rather than waiting for them (`CURLMOPT_QUICK_EXIT`).
    pub fn set_quick_exit(&mut self, quick: bool) {
        self.alive.set_quick_exit(quick);
    }

    /// The multi's limits on its connections.
    pub fn conn_limits_mut(&mut self) -> &mut ConnLimits {
        &mut self.limits
    }

    /// Add a transfer, to run at the next `perform` (`curl_multi_add_handle`).
    /// Everything the transfer can need from the multi's tables is
    /// reserved here, so running it allocates nothing in them.
    pub fn add(
        &mut self,
        easy: Box<Easy>,
        owner: H::Transfer,
        ev: &mut dyn MultiEvents<H>,
    ) -> Result<TransferId, AddError> {
        let added = self.add_unchecked(easy, owner, ev);
        self.check();
        added
    }

    fn add_unchecked(
        &mut self,
        easy: Box<Easy>,
        owner: H::Transfer,
        ev: &mut dyn MultiEvents<H>,
    ) -> Result<TransferId, AddError> {
        let refuse = |kind, easy| Err(AddError { kind, easy });
        if self.life == Life::Dead {
            // A dead multi starts over once its transfers are gone.
            if !self.slots.is_empty() {
                return refuse(MultiErrorKind::AbortedByCallback, easy);
            }
            self.life = Life::Alive;
            self.dirty.clear();
        }
        // A handle that performed on its own runs here from now on: its
        // private multi goes.
        let mut easy = easy;
        easy.private = None;
        #[cfg(feature = "debug-hooks")]
        if self.traces_internally
            && self.shutdowns.internal().is_none()
            && let Some(components) = easy.components()
        {
            self.trace_internally(components.clone());
        }
        let id = insert(
            Rows {
                slots: &mut self.slots,
                timers: &mut self.timers,
                dirty: &mut self.dirty,
                pending: &mut self.pending,
                notify: &mut self.notify,
            },
            &mut self.counts,
            &mut self.caches.pool,
            easy,
            Owner::App(owner),
        )
        .map_err(|(refused, _)| refused)?;
        let easy = &mut self.slots.get_mut(id).expect("just added").easy;
        // A connection the handle used itself, its last transfer having
        // only connected, is closed as its own multi runs it again
        // (`easy_perform`).
        if let Some(last) = easy.last_conn.filter(|l| l.used && self.handle_own) {
            self.close_reserved(id, last.id, ev);
        }
        // Its last connection is forgotten as it joins (`last_cpid`).
        let easy = &mut self.slots.get_mut(id).expect("just added").easy;
        easy.last_conn = None;
        self.dirty.insert(id.index());
        let owner = &self.slots.get(id).expect("just added").owner;
        ev.added(id, owner.host().expect("the application's own"));
        // The debug build says what it is, once for the multi, as the
        // first transfer comes (`multi_warn_debug`).
        #[cfg(feature = "debug-hooks")]
        if !std::mem::replace(&mut self.warned, true) {
            let now = self.clock.now();
            let mut cx = StepCx::new(id, self.rest(now, ev));
            crate::trace::info(&mut cx, format_args!("!!! WARNING !!!"));
            crate::trace::info(
                &mut cx,
                format_args!("This is a debug build of libcurl, do not use in production."),
            );
        }
        // Inside the add, as C, so the application hears of the 0 ms run.
        if let Err(kind) = self.update_timer(ev) {
            let slot = self.slots.remove(id).expect("just added");
            self.dirty.remove(id.index());
            self.counts.add_undone();
            return refuse(kind, slot.easy);
        }
        self.trace_membership(id, "added to", ev);
        Ok(id)
    }

    /// That transfer `id` came or goes (`curl_multi_add_handle`,
    /// `curl_multi_remove_handle`), as C numbers its transfers: its
    /// internal handle first, and counted.
    fn trace_membership(&mut self, id: TransferId, what: &str, ev: &mut dyn MultiEvents<H>) {
        let now = self.clock.now();
        trace_membership(&mut StepCx::new(id, self.rest(now, ev)), what);
    }

    /// Take a transfer out, completed or not, and give its `Easy` back
    /// (`curl_multi_remove_handle`). `None` if `id` is not in this multi.
    /// A transfer that had not completed gives its connection back as a
    /// premature end, and leaves no message.
    /// One the multi added for itself is not the application's to remove.
    pub fn remove(&mut self, id: TransferId, ev: &mut dyn MultiEvents<H>) -> Option<Removed<H>> {
        self.slots.app(id)?;
        let (easy, owner, status) = self.take_out(id, ev)?;
        let Owner::App(owner) = owner else {
            unreachable!("looked at above");
        };
        // What it had going on its behalf goes with it, whether or not a
        // lookup of its own dropped.
        self.reap(ev, true);
        self.check();
        Some(Removed {
            easy,
            owner,
            status,
        })
    }

    /// The internal transfers nobody wants any more taken out: those of a
    /// resolve that ended, or of a master gone. Called at the end of what
    /// may have ended one; `doh` says why a forgotten call is no leak of
    /// anything a stale probe can reach. They are looked for if a lookup
    /// dropped since the last look, or if `master_gone`.
    fn reap(&mut self, ev: &mut dyn MultiEvents<H>, master_gone: bool) {
        let due = self.reaping.due(master_gone);
        if !due || self.counts.internals() == 0 {
            return;
        }
        #[cfg(test)]
        {
            self.reaping.looked += 1;
        }
        let mut cursor = None;
        while let Some(id) = self.slots.next_after(cursor) {
            cursor = Some(id);
            if doh::orphan(&self.slots, id)
                && let Some((easy, owner, _)) = self.take_out(id, ev)
            {
                self.counts.internal_removed();
                if let Owner::Internal { host: Some(h), .. } = owner {
                    ev.internal_gone(easy, h);
                }
            }
        }
    }

    fn take_out(&mut self, id: TransferId, ev: &mut dyn MultiEvents<H>) -> Option<TakenOut<H>> {
        let run = self
            .slots
            .get_mut(id)?
            .run
            .take()
            .expect("no transfer is out while the multi is called");
        self.counts.removed(id.index(), run.state.is_completed());
        // Gone while alive (`multi_done`'s count, `curl_multi_remove_handle`).
        if run.alive {
            let mut tell = Telling {
                alive: &mut self.alive,
                slots: &mut self.slots,
                limits: &mut self.limits,
                notify: &mut self.notify,
                counts: &mut self.counts,
                sockets: &mut self.sockets,
                life: &mut self.life,
            };
            tell.went(ev);
        }
        self.abandon(id, run, ev);
        // A connection the handle only connected is closed as it leaves a
        // multi of the application's: no other can reach it (`multi_done`
        // of `curl_multi_remove_handle`).
        let easy = &self.slots.get(id).expect("still in the multi").easy;
        if !self.handle_own
            && easy.options().connect_only.reserves()
            && let Some(last) = easy.last_conn
        {
            self.close_reserved(id, last.id, ev);
        }
        // Whatever its state, it is traced as completed.
        let slot = self.slots.get_mut(id).expect("still in the multi");
        slot.mstate = mstate::MState::Completed;
        // Waiting on nothing now, which event handling assesses
        // (`Curl_multi_ev_xfer_done`); C does not mind the callback's
        // answer.
        if ev.wants_sockets() {
            let gone = PollsetTrace::gone(slot.pause);
            let now = self.clock.now();
            self.trace_pollset(id, now, gone, ev);
        }
        let _ = self.tell_wants(id, Wants::NONE, ev);
        self.trace_membership(id, "removed from", ev);
        let slot = self.slots.remove(id).expect("still in the multi");
        self.timers.remove(id);
        self.dirty.remove(id.index());
        // One waiting may run now (multi.c:867).
        let now = self.clock.now();
        self.wake_pending(now, ev);
        let status = self.update_timer(ev);
        Some((slot.easy, slot.owner, status))
    }

    /// Run every transfer that is not completed, in id order, then tell
    /// the application when to come back (`curl_multi_perform`). Returns
    /// how many are still running.
    pub fn perform(&mut self, ev: &mut dyn MultiEvents<H>) -> Result<u32, MultiErrorKind> {
        let running = self.perform_unchecked(ev);
        self.check();
        running
    }

    fn perform_unchecked(&mut self, ev: &mut dyn MultiEvents<H>) -> Result<u32, MultiErrorKind> {
        let now = self.clock.now();
        // On the internal handle, always among those C's perform runs.
        let running = self.counts.get().running;
        self.say(format_args!("multi_perform(running={running})"));
        self.take_answers();
        // The connections shutting down first, as C's internal handle is
        // the first it runs.
        self.drive_shutdowns(now, ev);
        let mut cursor = None;
        while let Some(id) = self.slots.next_after(cursor) {
            cursor = Some(id);
            self.run_single(id, now, ev);
        }
        self.schedule_if_changed(now, ev);
        self.dispatch(ev);
        // Timers due by the pass's start have been dealt with.
        while let Some(id) = self.timers.pop_due(now) {
            self.requeue_after_expiry(id, now);
        }
        self.shutdowns.expire(now);
        self.update_timer(ev)?;
        Ok(self.counts.get().running)
    }

    /// The transfers whose resolves the resolver has answered are run
    /// (`Curl_async_thrdd_multi_process`, the multi's own work). An answer
    /// for a transfer gone is for a setup closed, which cancelled it.
    fn take_answers(&mut self) {
        let (slots, dirty) = (&self.slots, &mut self.dirty);
        self.net.with_resolver(&mut |r| {
            r.answered(&mut |waiter| {
                if let Some(id) = waiter.0
                    && slots.get(id).is_some()
                {
                    dirty.insert(id.index());
                }
            });
        });
    }

    /// Move the shutdowns on (`Curl_cshutdn_perform`), as the multi's own
    /// work: what closes is told to the socket callback as the multi's.
    fn drive_shutdowns(&mut self, now: Instant, ev: &mut dyn MultiEvents<H>) {
        self.shutdowns.take_dirty();
        if self.shutdowns.is_empty() {
            return;
        }
        let tell = Telling {
            alive: &mut self.alive,
            slots: &mut self.slots,
            limits: &mut self.limits,
            notify: &mut self.notify,
            counts: &mut self.counts,
            sockets: &mut self.sockets,
            life: &mut self.life,
        };
        let mut net = Announcing::multi(&mut *self.net, tell, ev);
        self.shutdowns.perform(&mut net, now, &mut self.sockbuf);
    }

    /// A connection shutting down closed: one transfer waiting for room
    /// may find some (`multi_ischanged`, `multi_schedule_pending`).
    fn schedule_if_changed(&mut self, now: Instant, ev: &mut dyn MultiEvents<H>) {
        if self.shutdowns.take_changed() {
            self.wake_pending(now, ev);
        }
    }

    /// Let one transfer waiting for a connection look for one again
    /// (`multi_schedule_pending`), traced entering CONNECT as it is let.
    fn wake_pending(&mut self, now: Instant, ev: &mut dyn MultiEvents<H>) {
        if let Some(id) = state::wake_pending(&mut self.slots, &mut self.dirty, &mut self.pending) {
            let mut cx = StepCx::new(id, self.rest(now, ev));
            mstate::enter(&mut cx, mstate::MState::Connect);
        }
    }

    /// Run the transfers an event concerns (`curl_multi_socket_action`).
    pub fn socket_action(
        &mut self,
        what: SocketEvent,
        ev: &mut dyn MultiEvents<H>,
    ) -> Result<u32, MultiErrorKind> {
        let running = self.socket_action_unchecked(what, ev);
        self.check();
        running
    }

    fn socket_action_unchecked(
        &mut self,
        what: SocketEvent,
        ev: &mut dyn MultiEvents<H>,
    ) -> Result<u32, MultiErrorKind> {
        match what {
            // The application ran its timer: tell it the next one even if
            // unchanged.
            SocketEvent::Timeout => self.announce.forget(),
            // Every transfer waiting on it runs (`Curl_multi_ev_dirty_xfers`).
            SocketEvent::Socket(key) => {
                for user in self.sockets.users(key) {
                    match user {
                        SocketOwner::Transfer(id) => self.dirty.insert(id.index()),
                        SocketOwner::Conn(_) => self.shutdowns.mark_dirty(),
                        // Its answers are taken as the call starts.
                        SocketOwner::Resolver => {}
                    }
                }
            }
        }
        self.take_answers();
        let mut now = self.clock.now();
        self.mark_expired_dirty(now, ev);
        // A socket callback's abort ends the call before notifications and
        // the timer (`multi_socket`'s `goto out`).
        if self.run_dirty(now, ev)? > 0 {
            // Running took time: catch what came due meanwhile, once.
            now = self.clock.now();
            self.mark_expired_dirty(now, ev);
            self.run_dirty(now, ev)?;
        }
        self.schedule_if_changed(now, ev);
        self.dispatch(ev);
        self.update_timer(ev)?;
        Ok(self.counts.get().running)
    }

    /// The unread completion in the lowest row, marked read, whenever it
    /// completed (`curl_multi_info_read`).
    pub fn info_read(&mut self) -> Option<Message<'_, H>> {
        read_message(&self.slots, &mut self.counts)
    }

    /// What the transfers are doing now (`curl_multi_get_offt`).
    pub fn census(&self) -> Census {
        census_of(&self.slots, &self.counts)
    }

    /// Turn a kind of notification on or off
    /// (`curl_multi_notify_enable`, `curl_multi_notify_disable`). One
    /// already queued is not delivered once its kind is off.
    pub fn set_notify(&mut self, kind: NotifyKind, on: bool) {
        self.notify.set(kind, on);
    }

    /// How long until the multi should be driven: zero if something is
    /// ready, `None` if nothing is due (`curl_multi_timeout`).
    pub fn timeout(&self) -> Option<Duration> {
        match self.due() {
            Due::Now => Some(Duration::ZERO),
            Due::At(at) => Some(timers::wait_ms(self.clock.now(), at)),
            Due::Never => None,
        }
    }

    /// `timeout`, traced as C's `curl_multi_timeout` traces it: the timer
    /// that gives it, on its transfer.
    pub fn timeout_traced(&mut self, ev: &mut dyn MultiEvents<H>) -> Option<Duration> {
        let now = self.clock.now();
        self.multi_timeout(now, ev)
    }

    /// How long from `now` until the multi should be driven, as `timeout`
    /// says, the timer that gives it traced on its transfer
    /// (`multi_timeout`): none while something is ready.
    fn multi_timeout(&mut self, now: Instant, ev: &mut dyn MultiEvents<H>) -> Option<Duration> {
        let at = match self.due() {
            Due::Now => return Some(Duration::ZERO),
            Due::Never => return None,
            Due::At(at) => at,
        };
        let wait = timers::wait_ms(now, at);
        // The set's own deadline is its internal handle's, untraced.
        if let Some((first, id)) = self.timers.peek()
            && first == at
            && let Some(kind) = self.run_of(id).deadlines.first()
        {
            let ms = wait.as_millis();
            let mut cx = StepCx::new(id, self.rest(now, ev));
            state::trace_timer(&mut cx, kind, format_args!("gives multi timeout in {ms}ms"));
        }
        Some(wait)
    }

    /// Whether transfer `id` is one the multi works on (C's `process`
    /// set): neither completed nor waiting its turn.
    fn in_process(&self, id: TransferId) -> bool {
        let state = &self.run_of(id).state;
        !matches!(state, TransferState::Pending) && !state.is_completed()
    }

    /// Transfer `id`'s pollset traced as it is made (`Curl_multi_pollset`),
    /// from what `said` read of it.
    fn trace_pollset<T: Iterator<Item = (Instant, TimerKind)> + Clone>(
        &mut self,
        id: TransferId,
        now: Instant,
        said: PollsetTrace<T>,
        ev: &mut dyn MultiEvents<H>,
    ) {
        let mut cx = StepCx::new(id, self.rest(now, ev));
        said.trace(&mut cx);
    }

    /// Transfer `id`'s pollset, as it is now, traced.
    fn trace_pollset_now(
        &mut self,
        id: TransferId,
        now: Instant,
        ev: &mut dyn MultiEvents<H>,
    ) -> Result<(), OutOfMemory> {
        let slot = self.slots.get(id).expect("a transfer in the multi");
        // A transfer that is not verbose traces none of it: what it would
        // say is not worked out.
        if !slot.easy.options().output.verbose {
            return Ok(());
        }
        let run = slot
            .run
            .as_ref()
            .expect("no transfer is out while the multi is called");
        let said = run.pollset_trace(slot.pause, &self.caches.pool)?;
        self.trace_pollset(id, now, said, ev);
        Ok(())
    }

    /// Each pollset of the transfers the multi works on traced, in id
    /// order, as `multi_wait`, `curl_multi_fdset` and `curl_multi_waitfds`
    /// make them: the last of them, if any.
    fn trace_pollsets(
        &mut self,
        now: Instant,
        ev: &mut dyn MultiEvents<H>,
    ) -> Result<Option<TransferId>, OutOfMemory> {
        // The internal handle's first, as C's is the first in the set: the
        // resolver's wake while it is listened on, and the set's deadline
        // its one timer.
        let timers = usize::from(self.shutdowns.deadline().is_some());
        match self.alive.waker.as_deref().filter(|_| self.alive.count > 0) {
            Some(w) => {
                let alive = self.alive.count;
                self.say(format_args!("adding wakeup, {alive} xfers really alive"));
                let fd = SocketKey::of(w.fd()).get();
                self.say(format_args!("pollset[fd={fd} IN], timeouts={timers}"));
            }
            None => self.say(format_args!(
                "pollset[], timeouts={timers}, paused 0/0 (r/w)"
            )),
        }
        let mut last = None;
        let mut cursor = None;
        while let Some(id) = self.slots.next_after(cursor) {
            cursor = Some(id);
            if self.in_process(id) {
                self.trace_pollset_now(id, now, ev)?;
                last = Some(id);
            }
        }
        // Then the connections shutting down, each chain asked.
        self.shutdowns.say_pollsets(now);
        Ok(last)
    }

    pub fn counts(&self) -> Counts {
        self.counts.get()
    }

    /// Pause or unpause a transfer's directions from outside its handlers
    /// (`curl_easy_pause`): an unpause replays held output before it
    /// returns, and a change that leaves it running tells the timer.
    pub fn pause(
        &mut self,
        id: TransferId,
        req: PauseRequest,
        ev: &mut dyn MultiEvents<H>,
    ) -> Result<(), ErrorKind> {
        let now = self.clock.now();
        let was = self.slots.get(id).map(|s| s.pause);
        let result = pause_transfer(&mut self.rest(now, ev), id, req);
        // The timer hears only of a change: one that leaves the transfer
        // running, which it marks dirty (easy.c:1229).
        let timer = self
            .update_timer(ev)
            .map_err(|_| ErrorKind::AbortedByCallback);
        // Then the socket callback, of a change to a transfer not done
        // (easy.c:1233).
        let changed = self.slots.get(id).map(|s| s.pause) != was;
        let sockets = if result.is_ok()
            && timer.is_ok()
            && changed
            && !self.run_of(id).state.is_completed()
        {
            self.assess(id, ev)
                .map_err(|_| ErrorKind::AbortedByCallback)
        } else {
            Ok(())
        };
        self.check();
        result.and(timer).and(sockets)
    }

    /// The transfer after `after` in the multi, or the first; transfers
    /// added meanwhile may or may not be met.
    pub fn next_transfer(&self, after: Option<TransferId>) -> Option<TransferId> {
        let mut after = after;
        loop {
            let id = self.slots.next_after(after)?;
            if !self.slots.get(id).expect("just found").owner.is_internal() {
                return Some(id);
            }
            after = Some(id);
        }
    }

    /// What the application gave with the transfer when it added it, or
    /// what the host made for one of the multi's own.
    pub fn owner(&self, id: TransferId) -> Option<&H::Transfer> {
        self.slots.get(id).and_then(|s| s.owner.host())
    }

    /// What the application gave with each transfer, in id order
    /// (`curl_multi_get_handles`).
    pub fn owners(&self) -> impl Iterator<Item = &H::Transfer> {
        let mut cursor = None;
        std::iter::from_fn(move || {
            let id = self.next_transfer(cursor)?;
            cursor = Some(id);
            self.owner(id)
        })
    }

    pub fn easy(&self, id: TransferId) -> Option<&Easy> {
        self.slots.app(id).map(|s| &*s.easy)
    }

    /// Whether a transfer holds a connection, its own running or one it
    /// only made and has used (C's `data->conn`): from when it has found or
    /// started one until the connection goes back. `false` if `id` is not
    /// in this multi.
    pub fn holds_connection(&self, id: TransferId) -> bool {
        let Some(slot) = self.slots.app(id) else {
            return false;
        };
        slot.easy.holds_connection() || self.running_on_connection(id)
    }

    /// Whether a transfer is running on a connection, as opposed to one
    /// its handle only made.
    fn running_on_connection(&self, id: TransferId) -> bool {
        self.slots
            .get(id)
            .and_then(|slot| slot.run.as_ref())
            .is_some_and(|run| run.state.lease().is_some())
    }

    /// The transfer's handle, without what only the multi can decide: its
    /// share changes through [`Multi::set_share`].
    pub fn easy_mut(&mut self, id: TransferId) -> Option<EasyView<'_>> {
        self.slots.app_mut(id).map(|slot| slot.easy.view_as(id))
    }

    /// Use `share` for a transfer's next run, or none; refused while it
    /// holds a connection (`setopt_share`). `None` if `id` is not in this
    /// multi.
    pub fn set_share(
        &mut self,
        id: TransferId,
        share: Option<Share>,
    ) -> Option<Result<(), ShareInUse>> {
        if self.holds_connection(id) {
            return Some(Err(ShareInUse));
        }
        Some(self.slots.app_mut(id)?.easy.set_share(share))
    }

    /// As [`Multi::set_share`], `watch` told around each use the transfer
    /// makes of what the share keeps.
    pub fn set_share_watched(
        &mut self,
        id: TransferId,
        share: Share,
        watch: Handler<dyn ShareLock>,
    ) -> Option<Result<(), ShareInUse>> {
        if self.holds_connection(id) {
            return Some(Err(ShareInUse));
        }
        Some(self.slots.app_mut(id)?.easy.set_share_watched(share, watch))
    }

    /// Take a transfer off its share, a connection its handle only made
    /// going with it (`Curl_share_easy_unlink`); refused only while the
    /// transfer is running on a connection. `None` if `id` is not in this
    /// multi.
    pub fn leave_share(&mut self, id: TransferId) -> Option<Result<(), ShareInUse>> {
        let running = self.running_on_connection(id);
        let slot = self.slots.app_mut(id)?;
        if running {
            return Some(Err(ShareInUse));
        }
        slot.easy.leave_share();
        Some(Ok(()))
    }

    /// The TLS library's objects of the origin's connection a transfer
    /// holds, while it holds one, or of the one it only made once a call
    /// took that up (`CURLINFO_TLS_SSL_PTR`).
    pub fn tls_native(&self, id: TransferId) -> Option<TlsNative> {
        let slot = self.slots.app(id)?;
        tls_native_in(&self.slots, Some(&self.caches.pool), id)
            .or_else(|| raw::reserved_tls_native(Some(&self.caches.pool), &slot.easy))
    }

    fn run_of(&self, id: TransferId) -> &Run {
        run_in(&self.slots, id)
    }

    /// Where transfer `id` is, for the tests of what it holds.
    #[cfg(test)]
    pub(crate) fn state_of(&self, id: TransferId) -> &state::TransferState {
        &self.run_of(id).state
    }

    /// How many connections of shares are lent to it, for the tests.
    #[cfg(test)]
    pub(crate) fn lent_connections(&self) -> usize {
        self.caches.pool.lent_here()
    }

    /// Every socket the transfers wait on, and for what, in id order
    /// (`curl_multi_fdset`, `curl_multi_waitfds`), each transfer's pollset
    /// traced first.
    pub fn sockets(
        &mut self,
        ev: &mut dyn MultiEvents<H>,
        mut f: impl FnMut(SocketKey, Events),
    ) -> Result<(), MultiErrorKind> {
        let now = self.clock.now();
        self.trace_pollsets(now, ev)
            .map_err(|OutOfMemory| MultiErrorKind::OutOfMemory)?;
        // The resolver's wake first, as C's admin handle is the first in
        // the set it walks.
        if let Some(waker) = self.alive.waker.as_deref().filter(|_| self.alive.count > 0) {
            f(SocketKey::of(waker.fd()), Events::IN);
        }
        pollsets(
            &self.slots,
            &self.caches.pool,
            &self.shutdowns,
            |s, events| f(s.key(), events),
        )
        .map_err(|OutOfMemory| MultiErrorKind::OutOfMemory)
    }

    /// Fail every resolve of IPv6 addresses alone, as the debug build's
    /// `CURL_DBG_RESOLV_FAIL_IPV6` does, which the tests cannot set for
    /// one multi.
    #[cfg(all(test, feature = "debug-hooks"))]
    pub(crate) fn fail_ipv6_resolves(&mut self) {
        self.fail_ipv6 = true;
    }

    /// The multi but for the runs out of their slots, for a step or a
    /// call-out.
    fn rest<'a>(&'a mut self, now: Instant, ev: &'a mut dyn MultiEvents<H>) -> EngineRest<'a, H> {
        EngineRest {
            tell: Telling {
                alive: &mut self.alive,
                slots: &mut self.slots,
                limits: &mut self.limits,
                notify: &mut self.notify,
                counts: &mut self.counts,
                sockets: &mut self.sockets,
                life: &mut self.life,
            },
            caches: &mut self.caches,
            tls: &mut self.tls,
            sockbuf: &mut self.sockbuf,
            shutdowns: &mut self.shutdowns,
            pending: &mut self.pending,
            net: &mut *self.net,
            ipv6_works: self.ipv6_works,
            fail_ipv6: self.fail_ipv6,
            dirty: &mut self.dirty,
            timers: &mut self.timers,
            events: ev,
            now,
            clock: &self.clock,
            reaping: &mut self.reaping,
            discards: &mut self.discards,
            #[cfg(any(test, feature = "test-util"))]
            linger: self.linger,
        }
    }

    /// Tell the socket callback what transfer `id` now waits on
    /// (`Curl_multi_ev_assess_xfer`): nothing once it is out of the multi.
    fn assess(
        &mut self,
        id: TransferId,
        ev: &mut dyn MultiEvents<H>,
    ) -> Result<(), MultiErrorKind> {
        if !ev.wants_sockets() {
            return Ok(());
        }
        if self.slots.get(id).is_some() {
            let now = self.clock.now();
            self.trace_pollset_now(id, now, ev)
                .map_err(|OutOfMemory| MultiErrorKind::OutOfMemory)?;
        }
        let wants = match self.slots.get(id) {
            Some(slot) => {
                let run = slot
                    .run
                    .as_ref()
                    .expect("no transfer is out while the multi is called");
                run.state
                    .pollset(slot.pause, &self.caches.pool)
                    .map_err(|OutOfMemory| MultiErrorKind::OutOfMemory)?
                    .into_wants()
            }
            None => Wants::NONE,
        };
        self.tell_wants(id, wants, ev)
    }

    /// Tell the socket callback that transfer `id` waits on `wants`.
    fn tell_wants(
        &mut self,
        id: TransferId,
        wants: Wants,
        ev: &mut dyn MultiEvents<H>,
    ) -> Result<(), MultiErrorKind> {
        if !ev.wants_sockets() {
            return Ok(());
        }
        let mut changes = Vec::new();
        self.sockets
            .assess(SocketOwner::Transfer(id), wants.as_slice(), &mut changes)
            .map_err(|OutOfMemory| MultiErrorKind::OutOfMemory)?;
        cx::tell(
            &changes,
            SocketFor::Transfer(id),
            ev,
            &mut Telling {
                alive: &mut self.alive,
                slots: &mut self.slots,
                limits: &mut self.limits,
                notify: &mut self.notify,
                counts: &mut self.counts,
                sockets: &mut self.sockets,
                life: &mut self.life,
            },
        )
        .map_err(|Abort| MultiErrorKind::AbortedByCallback)
    }

    /// Tag socket `s` with the application's value, handed back to the
    /// socket callback (`curl_multi_assign`).
    pub fn assign(&mut self, s: SocketKey, value: Option<H::Socket>) -> Result<(), UnknownSocket> {
        self.sockets.assign(s, value)
    }

    /// Give back the connection of transfer `id`, whose `Run` is out of
    /// its slot, as a premature end: traced to the transfer, as C's
    /// `multi_done` runs with it still attached.
    fn abandon(&mut self, id: TransferId, run: Run, ev: &mut dyn MultiEvents<H>) {
        let now = self.clock.now();
        let mut cx = StepCx::new(id, self.rest(now, ev));
        run.abandon(&mut cx);
        cx.libraries_closed();
    }

    /// Step one transfer until it waits (`multi_runsingle`).
    /// Call `f` with transfer `id`'s step context, as a step would, its
    /// `Run` out of its slot.
    #[cfg(test)]
    pub(crate) fn with_step_cx<R>(
        &mut self,
        id: TransferId,
        f: impl FnOnce(&mut StepCx<'_, H>) -> R,
    ) -> R {
        let run = self.slots.get_mut(id).expect("in the multi").run.take();
        let now = self.clock.now();
        let mut quiet = NoEvents;
        let mut cx = StepCx::new(id, self.rest(now, &mut quiet));
        let r = f(&mut cx);
        if let Some(run) = run {
            put_back(&mut self.slots, &mut self.dirty, id, run);
        }
        r
    }

    fn run_single(&mut self, id: TransferId, now: Instant, ev: &mut dyn MultiEvents<H>) {
        self.dirty.remove(id.index());
        let slot = self.slots.get_mut(id).expect("a transfer in the multi");
        if slot.run.as_ref().is_some_and(|r| r.state.is_completed()) {
            return;
        }
        let mut run = slot.run.take().expect("not already out");
        if self.life == Life::Dead {
            // A callback aborted the multi: every transfer fails.
            let unstarted = matches!(run.state, TransferState::Init);
            // One waiting waits no longer (`mstate_enter_completed`).
            if matches!(run.state, TransferState::Pending) {
                self.pending
                    .take(id)
                    .expect("a waiting transfer's plan is queued");
            }
            run.state = std::mem::replace(&mut run.state, TransferState::Init)
                .fail(ErrorKind::AbortedByCallback);
            if unstarted {
                state::complete_unstarted(&mut slot.easy, now);
            }
        }
        let mut cx = StepCx::new(id, self.rest(now, ev));
        // The clock is read before each step, as C reads it at the top of
        // `multi_runsingle`'s loop: a step that took time, a `file:`
        // transfer's or a slow handler's, is timed and checked as it ends.
        // It runs again while a connection of the multi's changed, unless
        // it completed (`multi_runsingle`'s loop on `multi_ischanged`).
        while {
            cx.rest.now = cx.rest.clock.now();
            state::step(&mut run, &mut cx) == Wake::Again
                || (cx.rest.shutdowns.changed() && !run.state.is_completed())
        } {}
        // What the step dropped closed its libraries' sockets.
        cx.libraries_closed();
        // A second connection's setup, as the step left it.
        state::side_timers(&mut run, &mut cx);
        let now = cx.rest.now;
        // HTTP's wait for a 100 is derived from its state, never stored
        // apart from it; the server's time to answer stays armed until it
        // fires or the transfer completes, as C never clears it.
        match run.state.due() {
            Some((kind, at)) => {
                run.deadlines.arm_in(kind, now, at.since(now));
            }
            None => {
                run.deadlines.clear(TimerKind::Proto);
                run.deadlines.clear(TimerKind::FtpAccept);
            }
        }
        // A line protocol's, as the step last drove its back and forth.
        if let Some(at) = cx.server_response_at.take() {
            run.deadlines
                .arm_in(TimerKind::ServerResponse, now, at.since(now));
        }
        // The QUIC library's, as the step's last call asked for it.
        if let Some(at) = cx.quic_at.take() {
            run.deadlines.arm_in(TimerKind::Quic, now, at.since(now));
        }
        let completed = run.state.is_completed();
        // The application's completion posts a message, the first unread
        // one asking for a read (`multi_addmsg`); the multi's own leaves
        // none, its result told to its master.
        let mut first_unread = false;
        if completed {
            self.counts.completed();
            if !self
                .slots
                .get(id)
                .expect("a transfer in the multi")
                .owner
                .is_internal()
            {
                first_unread = self.counts.unread() == 0;
                self.counts.posted(id.index());
            }
            run.deadlines.clear_all();
            self.timers.remove(id);
        } else {
            self.timers.update(id, run.deadlines.wake_at());
        }
        put_back(&mut self.slots, &mut self.dirty, id, run);
        self.discard_unstarted(ev);
        let internal = match &self.slots.get(id).expect("just run").owner {
            Owner::App(_) => None,
            Owner::Internal { master, probe, .. } => Some((*master, probe.clone())),
        };
        match internal {
            // Told to its master, not to the application (`handle_completed`).
            Some((master, probe)) if completed => {
                let result = self.read_internal(id);
                let mut cx = StepCx::new(id, self.rest(now, ev));
                doh::probe_done(&mut cx, &probe, master, result);
            }
            Some(_) => {}
            None if completed => {
                // `Done` never outlasts a step, so this run went through it:
                // done, then its message posted (`mstate_enter_done`,
                // `multi_addmsg`).
                self.notify.push(Notification::EasyDone(id));
                if first_unread {
                    self.notify.push(Notification::InfoRead);
                }
                self.reap(ev, false);
            }
            None => self.reap(ev, false),
        }
    }

    /// The pushed transfers the step just run added and could not start
    /// are taken out, leaving no message, and their handles given back to
    /// the host to close, as C closes the handle its application's push
    /// callback took (`discard_newhandle`, through
    /// `Curl_multi_remove_handle`). C does it inside the read that offered
    /// the push; here the step's end is the first point where the
    /// transfer's connection is back with the multi (`DIVERGENCE.md`).
    /// The slots are looked through only if one was marked.
    fn discard_unstarted(&mut self, ev: &mut dyn MultiEvents<H>) {
        if !std::mem::take(&mut self.discards) {
            return;
        }
        let mut cursor = None;
        while let Some(id) = self.slots.next_after(cursor) {
            cursor = Some(id);
            if !self.slots.get(id).is_some_and(|s| s.discard) {
                continue;
            }
            // C's close does not mind the timer callback's answer; an
            // abort has left the multi dead meanwhile.
            let (easy, owner, _unminded) = self.take_out(id, ev).expect("just found");
            let Owner::App(owner) = owner else {
                unreachable!("a pushed transfer is the application's");
            };
            ev.unpushed(easy, owner);
        }
    }

    /// The result of the internal transfer `id`, which just completed, and
    /// which leaves no message.
    fn read_internal(&self, id: TransferId) -> Result<(), ErrorKind> {
        let TransferState::Completed(c) = &self.run_of(id).state else {
            unreachable!("just completed");
        };
        c.outcome
    }

    /// Deliver the pass's notifications (`Curl_mntfy_dispatch_all`). A
    /// handler may add, remove and read, but runs no transfer, so it queues
    /// nothing. One whose kind was turned off, or whose transfer is gone,
    /// is dropped.
    fn dispatch(&mut self, ev: &mut dyn MultiEvents<H>) {
        self.delivering = true;
        let mut i = 0;
        while let Some(n) = self.notify.get(i) {
            i += 1;
            let live = match n {
                Notification::InfoRead => true,
                Notification::EasyDone(id) => self.slots.get(id).is_some(),
            };
            if live && self.notify.is_enabled(n.kind()) {
                ev.notify(&mut NotifyCx { multi: self }, n);
            }
        }
        self.notify.clear();
        self.delivering = false;
    }

    /// Check every invariant in the debug build (`check.rs`).
    fn check(&self) {
        #[cfg(debug_assertions)]
        self.check_invariants(if self.delivering {
            check::At::Delivering
        } else {
            check::At::Rest
        });
    }

    /// Run the dirty transfers in id order, those made dirty meanwhile
    /// included (`multi_run_dirty`). Returns how many ran.
    fn run_dirty(
        &mut self,
        now: Instant,
        ev: &mut dyn MultiEvents<H>,
    ) -> Result<u32, MultiErrorKind> {
        let mut ran = 0;
        // The connections shutting down first, as C's internal handle's
        // row is the first.
        if self.shutdowns.is_dirty() {
            ran += 1;
            self.drive_shutdowns(now, ev);
        }
        let mut from = 0;
        while let Some(row) = self.dirty.first_from(from) {
            from = row + 1;
            let Some(id) = self.slots.key_at(row) else {
                self.dirty.remove(row);
                continue;
            };
            let mut cx = StepCx::new(id, self.rest(now, ev));
            mstate::trace(&mut cx, format_args!("multi_run_dirty"));
            if self.run_of(id).state.is_completed() {
                self.dirty.remove(row);
                continue;
            }
            ran += 1;
            self.run_single(id, now, ev);
            self.assess(id, ev)?;
        }
        Ok(ran)
    }

    /// Mark every transfer with a timer due by `now` dirty
    /// (`multi_mark_expired_as_dirty`).
    fn mark_expired_dirty(&mut self, now: Instant, ev: &mut dyn MultiEvents<H>) {
        if self.shutdowns.expire(now) {
            self.shutdowns.mark_dirty();
        }
        while let Some(id) = self.timers.pop_due(now) {
            if let Some(kind) = self.run_of(id).deadlines.first() {
                let mut cx = StepCx::new(id, self.rest(now, ev));
                state::trace_timer(&mut cx, kind, format_args!("has expired"));
            }
            self.requeue_after_expiry(id, now);
            self.dirty.insert(id.index());
        }
    }

    /// A transfer's timers due by `now` have fired; queue its next one
    /// (`add_next_timeout`).
    fn requeue_after_expiry(&mut self, id: TransferId, now: Instant) {
        let slot = self
            .slots
            .get_mut(id)
            .expect("a queued transfer is in the multi");
        let run = slot
            .run
            .as_mut()
            .expect("no transfer is out while the multi is called");
        run.deadlines.expire(now);
        let next = run.deadlines.wake_at();
        assert!(
            next.is_none_or(|at| at > now),
            "an expired timer stayed armed"
        );
        self.timers.update(id, next);
    }

    fn due(&self) -> Due {
        if self.life == Life::Dead
            || self.dirty.first_from(0).is_some()
            || self.shutdowns.is_dirty()
        {
            return Due::Now;
        }
        let transfers = self.timers.peek().map(|(at, _)| at);
        // The set's deadline is one row beside the transfers'.
        match transfers.into_iter().chain(self.shutdowns.deadline()).min() {
            Some(at) => Due::At(at),
            None => Due::Never,
        }
    }

    /// Tell the application's timer of a change (`Curl_update_timer`). An
    /// abort kills the multi.
    fn update_timer(&mut self, ev: &mut dyn MultiEvents<H>) -> Result<(), MultiErrorKind> {
        if !ev.wants_timer() || self.life == Life::Dead {
            return Ok(());
        }
        let now = self.clock.now();
        self.multi_timeout(now, ev);
        let Some(change) = self.announce.update(now, self.due()) else {
            return Ok(());
        };
        let mut cx = EventCx {
            alive: &self.alive,
            slots: &mut self.slots,
            limits: &mut self.limits,
            notify: &mut self.notify,
            counts: &mut self.counts,
            sockets: &mut self.sockets,
            pool: Some(&self.caches.pool),
        };
        ev.timer(&mut cx, change).map_err(|Abort| {
            self.life = Life::Dead;
            MultiErrorKind::AbortedByCallback
        })
    }
}

/// Every socket the transfers in `slots` wait on, and for what, in id
/// order, then those of the connections shutting down in `set`, oldest
/// first: the one computation behind waits, `fdset` and `waitfds`.
fn pollsets<'a, H: Host>(
    slots: &'a Slots<H>,
    pool: &'a Pool,
    set: &'a ShutdownSet,
    mut f: impl FnMut(&'a dyn Socket, Events),
) -> Result<(), OutOfMemory> {
    let mut cursor = None;
    while let Some(id) = slots.next_after(cursor) {
        cursor = Some(id);
        let slot = slots.get(id).expect("just found");
        let run = slot
            .run
            .as_ref()
            .expect("no transfer is out while the multi is called");
        for (socket, events) in run.state.pollset(slot.pause, pool)?.iter() {
            f(socket, events);
        }
    }
    for (socket, events) in set.pollsets() {
        f(socket, events);
    }
    Ok(())
}

/// What the transfers in `slots` are doing, `counts` being the multi's.
/// A transfer whose run is out of its slot is being stepped or replayed:
/// it neither waits for a connection nor has completed, and is skipped.
fn census_of<H: Host>(slots: &Slots<H>, counts: &Tally) -> Census {
    let mut pending = 0;
    let mut cursor = None;
    while let Some(id) = slots.next_after(cursor) {
        cursor = Some(id);
        let Some(run) = &slots.get(id).expect("just found").run else {
            continue;
        };
        if let TransferState::Pending = run.state {
            pending += 1;
        }
    }
    Census {
        counts: counts.get(),
        pending,
        unread: counts.unread(),
    }
}

/// The unread message in the lowest row, read (`curl_multi_info_read`).
fn read_message<'s, H: Host>(slots: &'s Slots<H>, counts: &mut Tally) -> Option<Message<'s, H>> {
    let (row, remaining) = counts.read_first()?;
    let id = slots
        .key_at(row)
        .expect("an unread message's transfer is in the multi");
    let TransferState::Completed(c) = &run_in(slots, id).state else {
        unreachable!("an unread message's transfer completed");
    };
    let owner = slots
        .get(id)
        .expect("just found")
        .owner
        .host()
        .expect("an internal transfer leaves no message");
    Some(Message {
        id,
        owner,
        result: c.outcome,
        remaining,
    })
}

fn run_in<H: Host>(slots: &Slots<H>, id: TransferId) -> &Run {
    let slot = slots.get(id).expect("a transfer in the multi");
    slot.run
        .as_ref()
        .expect("no transfer is out while the multi is called")
}

/// That the transfer `cx` is for came or goes, as C numbers its
/// transfers: its internal handle first, and counted.
fn trace_membership<H: Host>(cx: &mut StepCx<'_, H>, what: &str) {
    let Counts {
        running, current, ..
    } = cx.rest.tell.counts.get();
    let total = current + 1;
    // C's internal handle holds mid 0. A table that keeps its first row for
    // it (the C ABI's) numbers its rows as C does; one that does not starts
    // a row lower.
    let mid = cx.me.index() + u32::from(cx.rest.tell.slots.reserved() == 0);
    mstate::trace(
        cx,
        format_args!("{what} multi, mid={mid}, running={running}, total={total}"),
    );
}

/// What a transfer takes a row of.
struct Rows<'a, H: Host> {
    slots: &'a mut Slots<H>,
    timers: &'a mut TimerQueue<Transfer>,
    dirty: &'a mut RowSet,
    pending: &'a mut PendingQueue,
    notify: &'a mut NotifyQueue,
}

/// Give `easy` a slot, owned by `owner`, with a run of its own to come,
/// and number it as its pool does: the part of an add a step can make
/// too, for a transfer the server pushes. Refused, both come back.
fn insert<H: Host>(
    rows: Rows<'_, H>,
    counts: &mut Tally,
    pool: &mut Pool,
    easy: Box<Easy>,
    owner: Owner<H>,
) -> Result<TransferId, (AddError, Owner<H>)> {
    let refuse = |kind, easy, owner| Err((AddError { kind, easy }, owner));
    let Ok(vacancy) = rows.slots.reserve() else {
        return refuse(MultiErrorKind::OutOfMemory, easy, owner);
    };
    let n = vacancy.rows();
    if rows.timers.reserve(n).is_err()
        || counts.reserve(n).is_err()
        || rows.dirty.reserve(n).is_err()
        || rows.pending.reserve(n).is_err()
        || rows.notify.reserve(n).is_err()
    {
        return refuse(MultiErrorKind::OutOfMemory, easy, owner);
    }
    let slot = curl_alloc::try_box_or_back(Slot {
        owner,
        easy,
        pause: Pause::default(),
        judge_pause: false,
        speedometer: Speedometer::default(),
        rate: RateLimits::default(),
        run: Some(Run::new()),
        mstate: mstate::MState::Init,
        readers: None,
        closed: None,
        discard: false,
        holds: Default::default(),
    });
    let slot = match slot {
        Ok(slot) => slot,
        Err(Slot { easy, owner, .. }) => return refuse(MultiErrorKind::OutOfMemory, easy, owner),
    };
    let id = vacancy.fill(slot);
    counts.added();
    number(rows.slots, pool, id);
    Ok(id)
}

/// Number a transfer just added, as its pool does.
fn number<H: Host>(slots: &mut Slots<H>, pool: &mut Pool, id: TransferId) {
    // A transfer joins the pool, the share's if the share keeps
    // connections, under its lock, and is numbered by it
    // (`Curl_cpool_xfer_init`).
    let easy = &slots.get(id).expect("just added").easy;
    let number = match easy.shared(Kind::Connections) {
        Some(share) => {
            let watch = easy.share_watch();
            watched(watch, share, Kind::Connections, || share.pool().join())
        }
        None => pool.join(),
    };
    let easy = &mut slots.get_mut(id).expect("just added").easy;
    easy.report_mut().set_transfer(number);
}

/// Pause or unpause transfer `id` (the core of `curl_easy_pause`). An
/// unpause of held output replays it at once if the transfer's run is in
/// its slot; if it is out (the transfer is being stepped, or replayed
/// already), the replay sees the change before its next entry. A failed
/// replay leaves the output failed, and the transfer fails at its next
/// step.
fn pause_transfer<H: Host>(
    rest: &mut EngineRest<'_, H>,
    id: TransferId,
    req: PauseRequest,
) -> Result<(), ErrorKind> {
    let Some(slot) = rest.tell.slots.app_mut(id) else {
        return Err(ErrorKind::BadFunctionArgument);
    };
    // A run out of its slot is delivering output, so it has a connection.
    if slot.run.as_ref().is_some_and(|r| !r.state.holds_lease()) {
        return Err(ErrorKind::BadFunctionArgument);
    }
    let was = slot.pause;
    let was_held = was.recv == RecvPause::Held;
    slot.pause.apply(req);
    // A pause a reader asked for is lifted: each reader hears of it
    // (`Curl_creader_unpause`).
    let unpaused = (slot.pause.lifts() != was.lifts())
        .then_some(slot.readers)
        .flatten();
    // A direction that goes on measures its speed afresh, and its limit
    // starts over, the time paused earning nothing (`Curl_rlimit_block`).
    let resumed = [
        (Way::Recv, was.recv_paused() && !slot.pause.recv_paused()),
        (Way::Send, was.send_paused() && !slot.pause.send_paused()),
    ];
    if resumed.iter().any(|&(_, r)| r) {
        slot.speedometer.start_over();
    }
    for (way, _) in resumed.into_iter().filter(|&(_, r)| r) {
        let flow = &slot.easy.options().flow;
        slot.rate.start(way, flow, rest.now, None);
    }
    // Unless paused every way it moves bytes, the transfer runs again, and
    // is not slow for the time it was not (easy.c:1222). The ways are its
    // protocol's: a run out of its slot is judged when it is back.
    match &slot.run {
        Some(run) => {
            if !slot.pause.blocks(run.state.directions(slot.easy.options())) {
                slot.speedometer.forget_slow();
                rest.dirty.insert(id.index());
            }
        }
        None => slot.judge_pause = true,
    }
    let replay = was_held && slot.pause.recv == RecvPause::Running;
    // The connection hears of a change to receiving, once held output is
    // replayed (`Curl_xfer_pause_recv`).
    let paused = slot.pause.recv_paused();
    let tell = (was.recv_paused() != paused).then_some(paused);
    let run = if replay || tell.is_some() {
        slot.run.take()
    } else {
        None
    };
    if let Some(readers) = unpaused {
        let mut cx = StepCx::new(id, rest.reborrow());
        readers.trace_unpause(&mut cx);
    }
    let Some(mut run) = run else {
        return Ok(());
    };
    let mut cx = StepCx::new(id, rest.reborrow());
    let replayed = if replay {
        state::flush(&mut run, &mut cx)
    } else {
        Ok(())
    };
    if let Some(paused) = tell {
        // A replay its handler paused again told the connection so as it
        // paused (`cw_out`'s `Curl_xfer_pause_recv`), before the unpause
        // does, whatever the replay came to.
        if !paused && cx.pause().recv == RecvPause::Held {
            run.state.data_pause(&mut cx, true);
        }
        run.state.data_pause(&mut cx, paused);
    }
    put_back(rest.tell.slots, rest.dirty, id, run);
    replayed
}

/// The TLS library's objects of the connection transfer `id`, whose run
/// is in its slot, holds.
fn tls_native_in<H: Host>(
    slots: &Slots<H>,
    pool: Option<&Pool>,
    id: TransferId,
) -> Option<TlsNative> {
    slots.get(id)?.run.as_ref()?.state.tls_native(pool)
}

/// Put transfer `id`'s run back in its slot, and judge a pause its own
/// handler asked for while the run was out, as `pause_transfer` judges
/// one asked for while it is in.
fn put_back<H: Host>(slots: &mut Slots<H>, dirty: &mut RowSet, id: TransferId, run: Run) {
    let slot = slots.get_mut(id).expect("still in the multi");
    if std::mem::take(&mut slot.judge_pause)
        && !slot.pause.blocks(run.state.directions(slot.easy.options()))
    {
        slot.speedometer.forget_slow();
        dirty.insert(id.index());
    }
    slot.run = Some(run);
}

impl<H: Host> Multi<H> {
    /// Close the multi's connections, as `curl_multi_cleanup` does once
    /// its transfers are out (`Curl_cpool_destroy`,
    /// `Curl_cshutdn_destroy`): each idle one is shut down once, and those
    /// that do not finish join the set; the set has one pass more (or,
    /// with `debug-hooks`, as long as `CURL_GRACEFUL_SHUTDOWN` says, in
    /// milliseconds), and what is left is closed. The socket callback in
    /// `ev` hears of each socket that closes, as the multi's own.
    pub fn close_connections(&mut self, ev: &mut dyn MultiEvents<H>) {
        if self.closed {
            assert!(
                self.caches.pool.len() == 0 && self.shutdowns.is_empty(),
                "a multi whose connections were closed made more"
            );
            return;
        }
        self.closed = true;
        let n = self.caches.pool.len();
        self.say(format_args!("[CPOOL] destroy, {n} connections"));
        self.terminate_connections(ev);
        self.say(format_args!("multi_cleanup, closing admin handle, done"));
    }

    /// The network changed (`CURLMOPT_NETWORK_CHANGED`): forget the
    /// names resolved if `names`, and if `connections`, reuse no
    /// connection made before and close each no transfer uses
    /// (`Curl_dnscache_clear`, `Curl_cpool_nw_changed`). The socket
    /// callback in `ev` hears of each socket that closes or waits to.
    pub fn network_changed(&mut self, names: bool, connections: bool, ev: &mut dyn MultiEvents<H>) {
        if names {
            self.caches.dns = crate::conn::DnsCache::default();
        }
        if !connections {
            return;
        }
        let now = self.clock.now();
        let max_total = self.limits.max_total;
        let mut tell = Telling {
            alive: &mut self.alive,
            slots: &mut self.slots,
            limits: &mut self.limits,
            notify: &mut self.notify,
            counts: &mut self.counts,
            sockets: &mut self.sockets,
            life: &mut self.life,
        };
        {
            let mut net = Announcing::multi(&mut *self.net, tell.reborrow(), &mut *ev);
            let mut exits = WithSet {
                net: &mut net,
                set: &mut self.shutdowns,
                max_total,
                multi_pool: None,
                room: &mut self.sockbuf,
            };
            self.caches.pool.network_changed(&mut exits, now);
        }
        cx::announce_closing(&mut self.shutdowns, &mut *self.net, &mut tell, ev, now);
    }

    /// Keep alive the connections of transfer `id`'s pool that have gone
    /// its upkeep interval without (`curl_easy_upkeep`): an HTTP/2
    /// connection is sent a PING, others nothing. The socket callback in
    /// `ev` hears of each socket that closes or waits to. `None` if `id`
    /// is not in this multi.
    pub fn upkeep(
        &mut self,
        id: TransferId,
        ev: &mut dyn MultiEvents<H>,
    ) -> Option<Result<(), OutOfMemory>> {
        let easy = &self.slots.app(id)?.easy;
        let interval = easy.options().limits.reuse.upkeep.0;
        let share = easy.shared(Kind::Connections).cloned();
        let watch = easy.share_watch.clone();
        Some(self.upkeep_with(interval, share.as_ref().map(|s| (s, watch)), ev))
    }

    /// As `upkeep`, for `easy`, not added, whose transfers this multi
    /// ran.
    pub fn upkeep_for(
        &mut self,
        easy: &Easy,
        ev: &mut dyn MultiEvents<H>,
    ) -> Result<(), OutOfMemory> {
        let interval = easy.options().limits.reuse.upkeep.0;
        let share = easy.shared(Kind::Connections).cloned();
        let watch = easy.share_watch.clone();
        self.upkeep_with(interval, share.as_ref().map(|s| (s, watch)), ev)
    }

    fn upkeep_with(
        &mut self,
        interval: std::time::Duration,
        share: Option<(&Share, Option<Handler<dyn ShareLock>>)>,
        ev: &mut dyn MultiEvents<H>,
    ) -> Result<(), OutOfMemory> {
        let now = self.clock.now();
        let max_total = self.limits.max_total;
        let mut tell = Telling {
            alive: &mut self.alive,
            slots: &mut self.slots,
            limits: &mut self.limits,
            notify: &mut self.notify,
            counts: &mut self.counts,
            sockets: &mut self.sockets,
            life: &mut self.life,
        };
        let kept = {
            let mut net = Announcing::multi(&mut *self.net, tell.reborrow(), &mut *ev);
            let share = share.as_ref().map(|(s, w)| (*s, w.as_deref()));
            cx::upkeep(
                &mut self.caches.pool,
                share,
                &mut net,
                Linger {
                    set: &mut self.shutdowns,
                    max_total,
                    multi_pool: None,
                    room: &mut self.sockbuf,
                },
                interval,
                now,
            )
        };
        cx::announce_closing(&mut self.shutdowns, &mut *self.net, &mut tell, ev, now);
        kept
    }

    /// A line of the multi's internal trace, in `MULTI`'s name.
    fn say(&self, line: std::fmt::Arguments<'_>) {
        if let Some(t) = self.shutdowns.internal() {
            t.of(crate::components::Component::Multi, line);
        }
    }

    /// Close every connection, through the set (`Curl_cpool_destroy`,
    /// `Curl_cshutdn_destroy`).
    fn terminate_connections(&mut self, ev: &mut dyn MultiEvents<H>) {
        let now = self.clock.now();
        let max_total = self.limits.max_total;
        {
            let tell = Telling {
                alive: &mut self.alive,
                slots: &mut self.slots,
                limits: &mut self.limits,
                notify: &mut self.notify,
                counts: &mut self.counts,
                sockets: &mut self.sockets,
                life: &mut self.life,
            };
            let mut net = Announcing::multi(&mut *self.net, tell, &mut *ev);
            let mut exits = WithSet {
                net: &mut net,
                set: &mut self.shutdowns,
                max_total,
                multi_pool: None,
                room: &mut self.sockbuf,
            };
            self.caches.pool.close_idle(&mut exits, now);
        }
        let mut tell = Telling {
            alive: &mut self.alive,
            slots: &mut self.slots,
            limits: &mut self.limits,
            notify: &mut self.notify,
            counts: &mut self.counts,
            sockets: &mut self.sockets,
            life: &mut self.life,
        };
        cx::announce_closing(
            &mut self.shutdowns,
            &mut *self.net,
            &mut tell,
            &mut *ev,
            now,
        );
        if self.shutdowns.is_empty() {
            return;
        }
        let limit = graceful_shutdown();
        let mut net = Announcing::multi(&mut *self.net, tell, ev);
        let say = |set: &ShutdownSet, line: std::fmt::Arguments<'_>| {
            if let Some(t) = set.internal() {
                t.of(crate::components::Component::Multi, line);
            }
        };
        let (n, ms) = (self.shutdowns.len(), limit.as_millis());
        say(
            &self.shutdowns,
            format_args!("[SHUTDOWN] destroy, {n} connections, timeout={ms}ms"),
        );
        say(&self.shutdowns, format_args!("[SHUTDOWN] shutdown all"));
        // `cshutdn_terminate_all`: a pass, then a wait for its sockets,
        // until all are done or the time is spent.
        loop {
            self.shutdowns
                .perform(&mut net, self.clock.now(), &mut self.sockbuf);
            if self.shutdowns.is_empty() {
                say(
                    &self.shutdowns,
                    format_args!("[SHUTDOWN] shutdown finished cleanly"),
                );
                break;
            }
            let at = self.clock.now();
            // In milliseconds, as C counts them.
            let spent_ms = at.ms_since(now);
            let limit_ms = crate::time::millis(limit);
            let spent = Duration::from_millis(spent_ms.max(0).unsigned_abs());
            // A goodbye awaiting its answer is waited for in its own
            // time, as C's protocol disconnect blocks for it.
            let answer = self.shutdowns.answer_time_left(at);
            if spent_ms >= limit_ms && answer.is_none() {
                let why = if limit.is_zero() {
                    "best effort done"
                } else {
                    "timeout"
                };
                say(
                    &self.shutdowns,
                    format_args!("[SHUTDOWN] shutdown finished, {why}"),
                );
                break;
            }
            let left = limit.saturating_sub(spent).max(answer.unwrap_or_default());
            let wait = left.min(Duration::from_secs(1));
            if wait_for(&self.shutdowns, &mut net, wait).is_err() {
                say(
                    &self.shutdowns,
                    format_args!("[SHUTDOWN] shutdown finished, aborted"),
                );
                break;
            }
        }
        self.shutdowns.close_all(&mut net);
        // Nothing is left to schedule.
        self.shutdowns.take_changed();
    }
}

/// How long a multi's cleanup lets its connections shut down: no longer
/// than one pass, or with `debug-hooks` what `CURL_GRACEFUL_SHUTDOWN` says,
/// in milliseconds up to `INT_MAX` (`Curl_cshutdn_destroy`).
fn graceful_shutdown() -> Duration {
    #[cfg(feature = "debug-hooks")]
    {
        let mut buf = [0u8; 32];
        if let Some(given) = curl_os::env::var_into(b"CURL_GRACEFUL_SHUTDOWN", &mut buf)
            && let Some(ms) = leading_ms(given)
        {
            return Duration::from_millis(u64::from(ms));
        }
    }
    Duration::ZERO
}

/// The number `text` starts with, what follows it ignored, if it starts
/// with one no greater than `INT_MAX` (`curlx_str_number`).
#[cfg(feature = "debug-hooks")]
fn leading_ms(text: &[u8]) -> Option<u32> {
    let digits = text.iter().take_while(|b| b.is_ascii_digit());
    let mut n: Option<u32> = None;
    for &d in digits {
        let next = n
            .unwrap_or(0)
            .checked_mul(10)?
            .checked_add(u32::from(d - b'0'))?;
        if next > i32::MAX.unsigned_abs() {
            return None;
        }
        n = Some(next);
    }
    n
}

/// Wait up to `wait` for the sockets the connections in `set` wait on
/// (`cshutdn_wait`).
fn wait_for(
    set: &ShutdownSet,
    net: &mut dyn Net,
    wait: Duration,
) -> Result<(), curl_alloc::OutOfMemory> {
    use curl_alloc::TryVec as _;
    let mut polls = Vec::new();
    polls
        .try_reserve_exact(set.len())
        .map_err(|_| curl_alloc::OutOfMemory)?;
    for (socket, events) in set.pollsets() {
        polls
            .try_push(crate::conn::io::SocketPoll::new(socket, events))
            .expect("reserved");
    }
    // A failed poll is a wait that ended.
    let _ = net.poll(&mut polls, &mut [], wait);
    Ok(())
}

impl<H: Host> Drop for Multi<H> {
    /// Take out every transfer still in the multi, giving back its
    /// connection, then close its connections (`curl_multi_cleanup`).
    fn drop(&mut self) {
        let mut cursor = None;
        while let Some(id) = self.slots.next_after(cursor) {
            cursor = Some(id);
            let slot = self.slots.get_mut(id).expect("just found");
            if let Some(run) = slot.run.take() {
                self.abandon(id, run, &mut NoEvents);
            }
        }
        self.close_connections(&mut NoEvents);
    }
}

#[cfg(test)]
mod doh_tests;
#[cfg(test)]
mod props;
#[cfg(test)]
mod shutdown_tests;
#[cfg(test)]
mod socket_tests;
#[cfg(test)]
mod tests;
