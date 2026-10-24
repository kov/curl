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
mod cx;
pub(crate) mod mstate;
mod notify;
mod sched;
mod sockets;
pub(crate) mod state;
pub(crate) mod timers;
mod wait;

use std::num::NonZeroU32;
use std::time::Duration;

use curl_alloc::{OutOfMemory, TryArc};

use crate::conn::io::{Events, Net, Socket, SocketKey, Waker};
use crate::conn::shutdown::{ShutdownSet, WithSet};
use crate::conn::{AddLimits, Caches};
use crate::deliver::{Pause, RecvPause, SendPause};
use crate::easy::Easy;
use crate::error::{ErrorKind, MultiErrorKind};
use crate::id::{Arena, ArenaPolicy, Key};
use crate::progress::Speedometer;
use crate::progress::rate::{RateLimits, Way};
use crate::share::{Kind, watched};
use crate::time::{Clock, Instant};
use crate::tls::{TlsNative, TlsShared};
use crate::upload::Readers;

pub use crate::deliver::PauseRequest;
use cx::{Announcing, EngineRest, Telling};
pub use cx::{EventCx, NotifyCx, TransferCx};
pub use notify::{Notification, NotifyKind};
pub use sched::{Census, Counts};
pub use sockets::{SocketFor, SocketWhat, UnknownSocket};
pub use timers::TimerChange;
pub use wait::{WaitMode, drive_by_events, drive_to_completion};

use notify::NotifyQueue;
use sched::{RowSet, Tally};
use sockets::{SocketOwner, SocketTable, Wants};
use state::{Message as MessageState, PollsetTrace, Run, StepCx, TransferState, Wake};
use timers::{Due, TimerAnnounce, TimerKind, TimerQueue};

/// The application's types a multi carries: a value per transfer, handed
/// back with its messages and on removal, and a value per socket it
/// watches, handed back to its socket callback (`curl_multi_assign`).
pub trait Host {
    type Transfer;
    type Socket: Copy;
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
    /// inside the add may.
    fn added(&mut self, id: TransferId, owner: &H::Transfer) {
        let _ = (id, owner);
    }

    /// Whether `timer` is wanted. Without it the multi keeps no record of
    /// what it announced, as C without a timer callback.
    fn wants_timer(&self) -> bool {
        false
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

/// How a multi is made: its clock, its network, the ids it hands out, and
/// the waker other threads use to interrupt its waits. Without a waker,
/// nothing can (C always makes one; the shim does too).
pub struct Env {
    pub clock: Box<dyn Clock>,
    pub net: Box<dyn Net + Send>,
    pub arena: ArenaPolicy,
    pub waker: Option<TryArc<Waker>>,
}

/// The multi's state after a callback's abort.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Life {
    Alive,
    /// Every transfer fails; nothing is added until the multi is empty.
    Dead,
}

struct Slot<H: Host> {
    owner: H::Transfer,
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

/// The multi's limits on its connections; none set by default.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
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
    /// The connections shutting down, whichever pool they left.
    shutdowns: ShutdownSet,
    limits: ConnLimits,
    /// The transfer last let look for a connection again.
    pending_after: Option<TransferId>,
    sockets: SocketTable<H::Socket>,
    clock: Box<dyn Clock>,
    net: Box<dyn Net + Send>,
    /// IPv6 works here, as the network said once as the multi was made
    /// (`Curl_probeipv6`, `multi->ipv6_works`): a property of the system
    /// its transfers run on, kept by the root they reach it through.
    ipv6_works: bool,
    waker: Option<TryArc<Waker>>,
    counts: Tally,
    life: Life,
    /// A transfer was told the library is a debug build.
    #[cfg(feature = "debug-hooks")]
    warned: bool,
    /// The tests' layer each connection set up from here is given.
    #[cfg(any(test, feature = "test-util"))]
    linger: Option<crate::conn::layer::Linger>,
}

impl<H: Host> Multi<H> {
    pub fn new(env: Env) -> Result<Self, OutOfMemory> {
        let slots = Arena::new(env.arena)?;
        let caches = Caches::new()?;
        // As C's multi is made, after its waker (`Curl_multi_handle`).
        let mut net = env.net;
        let ipv6_works = net.probe_ipv6()?;
        Ok(Multi {
            slots,
            dirty: RowSet::default(),
            timers: TimerQueue::new(),
            announce: TimerAnnounce::default(),
            notify: NotifyQueue::default(),
            delivering: false,
            caches,
            tls: None,
            shutdowns: ShutdownSet::default(),
            limits: ConnLimits::default(),
            pending_after: None,
            sockets: SocketTable::new(),
            clock: env.clock,
            net,
            ipv6_works,
            waker: env.waker,
            counts: Tally::default(),
            life: Life::Alive,
            #[cfg(feature = "debug-hooks")]
            warned: false,
            #[cfg(any(test, feature = "test-util"))]
            linger: None,
        })
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
        let Ok(vacancy) = self.slots.reserve() else {
            return refuse(MultiErrorKind::OutOfMemory, easy);
        };
        let rows = vacancy.rows();
        if self.timers.reserve(rows).is_err()
            || self.dirty.reserve(rows).is_err()
            || self.notify.reserve(rows).is_err()
        {
            return refuse(MultiErrorKind::OutOfMemory, easy);
        }
        let run = Run::new();
        let slot = curl_alloc::try_box_or_back(Slot {
            owner,
            easy,
            pause: Pause::default(),
            judge_pause: false,
            speedometer: Speedometer::default(),
            rate: RateLimits::default(),
            run: Some(run),
            mstate: mstate::MState::Init,
            readers: None,
        });
        let slot = match slot {
            Ok(slot) => slot,
            Err(slot) => return refuse(MultiErrorKind::OutOfMemory, slot.easy),
        };
        let id = vacancy.fill(slot);
        self.counts.added();
        // A transfer joins the pool, the share's if the share keeps
        // connections, under its lock, and is numbered by it
        // (`Curl_cpool_xfer_init`).
        let easy = &self.slots.get(id).expect("just added").easy;
        let number = match easy.share().filter(|s| s.keeps(Kind::Connections)) {
            Some(share) => {
                let watch = easy.share_watch();
                watched(watch, share, Kind::Connections, || share.pool().join())
            }
            None => self.caches.pool.join(),
        };
        let easy = &mut self.slots.get_mut(id).expect("just added").easy;
        easy.report_mut().set_transfer(number);
        self.dirty.insert(id.index());
        ev.added(id, &self.slots.get(id).expect("just added").owner);
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
        let Counts {
            running, current, ..
        } = self.counts.get();
        let total = current + 1;
        let now = self.clock.now();
        let mut cx = StepCx::new(id, self.rest(now, ev));
        let mid = id.index() + 1;
        mstate::trace(
            &mut cx,
            format_args!("{what} multi, mid={mid}, running={running}, total={total}"),
        );
    }

    /// Take a transfer out, completed or not, and give its `Easy` back
    /// (`curl_multi_remove_handle`). `None` if `id` is not in this multi.
    /// A transfer that had not completed gives its connection back as a
    /// premature end, and leaves no message.
    pub fn remove(&mut self, id: TransferId, ev: &mut dyn MultiEvents<H>) -> Option<Removed<H>> {
        let removed = self.remove_unchecked(id, ev);
        self.check();
        removed
    }

    fn remove_unchecked(
        &mut self,
        id: TransferId,
        ev: &mut dyn MultiEvents<H>,
    ) -> Option<Removed<H>> {
        let run = self
            .slots
            .get_mut(id)?
            .run
            .take()
            .expect("no transfer is out while the multi is called");
        self.counts.removed(run.state.is_completed());
        self.abandon(id, run, ev);
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
        Some(Removed {
            easy: slot.easy,
            owner: slot.owner,
            status,
        })
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

    /// Move the shutdowns on (`Curl_cshutdn_perform`), as the multi's own
    /// work: what closes is told to the socket callback as the multi's.
    fn drive_shutdowns(&mut self, now: Instant, ev: &mut dyn MultiEvents<H>) {
        self.shutdowns.take_dirty();
        if self.shutdowns.is_empty() {
            return;
        }
        let tell = Telling {
            slots: &mut self.slots,
            limits: &mut self.limits,
            notify: &mut self.notify,
            counts: &self.counts,
            sockets: &mut self.sockets,
            life: &mut self.life,
        };
        let mut net = Announcing::multi(&mut *self.net, tell, ev);
        self.shutdowns.perform(&mut net, now);
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
        if let Some(id) =
            state::wake_pending(&mut self.slots, &mut self.dirty, &mut self.pending_after)
        {
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
                    }
                }
            }
        }
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

    /// The oldest-added unread completion, marked read
    /// (`curl_multi_info_read`).
    pub fn info_read(&mut self) -> Option<Message<'_, H>> {
        read_message(&mut self.slots)
    }

    /// What the transfers are doing now (`curl_multi_get_offt`).
    pub fn census(&self) -> Census {
        census_of(&self.slots, self.counts.get())
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
        !matches!(state, TransferState::Pending(_)) && !state.is_completed()
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
    fn trace_pollset_now(&mut self, id: TransferId, now: Instant, ev: &mut dyn MultiEvents<H>) {
        let slot = self.slots.get(id).expect("a transfer in the multi");
        let run = slot
            .run
            .as_ref()
            .expect("no transfer is out while the multi is called");
        let said = run.pollset_trace(slot.pause);
        self.trace_pollset(id, now, said, ev);
    }

    /// Each pollset of the transfers the multi works on traced, in id
    /// order, as `multi_wait`, `curl_multi_fdset` and `curl_multi_waitfds`
    /// make them: the last of them, if any.
    fn trace_pollsets(&mut self, now: Instant, ev: &mut dyn MultiEvents<H>) -> Option<TransferId> {
        let mut last = None;
        let mut cursor = None;
        while let Some(id) = self.slots.next_after(cursor) {
            cursor = Some(id);
            if self.in_process(id) {
                self.trace_pollset_now(id, now, ev);
                last = Some(id);
            }
        }
        last
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
        self.slots.next_after(after)
    }

    /// What the application gave with the transfer when it added it.
    pub fn owner(&self, id: TransferId) -> Option<&H::Transfer> {
        self.slots.get(id).map(|s| &s.owner)
    }

    pub fn easy(&self, id: TransferId) -> Option<&Easy> {
        self.slots.get(id).map(|s| &*s.easy)
    }

    pub fn easy_mut(&mut self, id: TransferId) -> Option<&mut Easy> {
        self.slots.get_mut(id).map(|s| &mut *s.easy)
    }

    /// The TLS library's objects of the origin's connection a transfer
    /// holds, while it holds one (`CURLINFO_TLS_SSL_PTR`).
    pub fn tls_native(&self, id: TransferId) -> Option<TlsNative> {
        tls_native_in(&self.slots, id)
    }

    fn run_of(&self, id: TransferId) -> &Run {
        run_in(&self.slots, id)
    }

    /// Where transfer `id` is, for the tests of what it holds.
    #[cfg(test)]
    pub(crate) fn state_of(&self, id: TransferId) -> &state::TransferState {
        &self.run_of(id).state
    }

    /// Every socket the transfers wait on, and for what, in id order
    /// (`curl_multi_fdset`, `curl_multi_waitfds`), each transfer's pollset
    /// traced first.
    pub fn sockets(&mut self, ev: &mut dyn MultiEvents<H>, f: impl FnMut(&dyn Socket, Events)) {
        let now = self.clock.now();
        self.trace_pollsets(now, ev);
        pollsets(&self.slots, &self.shutdowns, f);
    }

    /// The multi but for the runs out of their slots, for a step or a
    /// call-out.
    fn rest<'a>(&'a mut self, now: Instant, ev: &'a mut dyn MultiEvents<H>) -> EngineRest<'a, H> {
        EngineRest {
            tell: Telling {
                slots: &mut self.slots,
                limits: &mut self.limits,
                notify: &mut self.notify,
                counts: &self.counts,
                sockets: &mut self.sockets,
                life: &mut self.life,
            },
            caches: &mut self.caches,
            tls: &mut self.tls,
            shutdowns: &mut self.shutdowns,
            pending_after: &mut self.pending_after,
            net: &mut *self.net,
            ipv6_works: self.ipv6_works,
            dirty: &mut self.dirty,
            events: ev,
            now,
            clock: &*self.clock,
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
            self.trace_pollset_now(id, now, ev);
        }
        let wants = self.slots.get(id).map_or(Wants::NONE, |slot| {
            let run = slot
                .run
                .as_ref()
                .expect("no transfer is out while the multi is called");
            run.state.pollset(slot.pause).wants()
        });
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
                slots: &mut self.slots,
                limits: &mut self.limits,
                notify: &mut self.notify,
                counts: &self.counts,
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
        run.state.abandon(&mut cx);
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
        while {
            cx.rest.now = cx.rest.clock.now();
            state::step(&mut run, &mut cx) == Wake::Again
        } {}
        let now = cx.rest.now;
        // The protocol's own wait is derived from its state, never stored
        // apart from it.
        match run.state.wake_at() {
            Some(at) => {
                run.deadlines.arm_in(TimerKind::Proto, now, at.since(now));
            }
            None => run.deadlines.clear(TimerKind::Proto),
        }
        let completed = run.state.is_completed();
        if completed {
            self.counts.completed();
            run.deadlines.clear_all();
            self.timers.remove(id);
        } else {
            self.timers.update(id, run.deadlines.wake_at());
        }
        put_back(&mut self.slots, &mut self.dirty, id, run);
        if completed {
            // `Done` never outlasts a step, so this run went through it:
            // done, then its message posted (`mstate_enter_done`,
            // `multi_addmsg`).
            self.notify.push(Notification::EasyDone(id));
            if !self.unread_besides(id) {
                self.notify.push(Notification::InfoRead);
            }
        }
    }

    /// Whether a transfer other than `id` has an unread message.
    fn unread_besides(&self, id: TransferId) -> bool {
        let mut cursor = None;
        while let Some(other) = self.slots.next_after(cursor) {
            cursor = Some(other);
            if other != id
                && let TransferState::Completed(c) = &self.run_of(other).state
                && c.message == MessageState::Unread
            {
                return true;
            }
        }
        false
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
            slots: &mut self.slots,
            limits: &mut self.limits,
            notify: &mut self.notify,
            counts: self.counts.get(),
            sockets: &mut self.sockets,
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
    set: &'a ShutdownSet,
    mut f: impl FnMut(&'a dyn Socket, Events),
) {
    let mut cursor = None;
    while let Some(id) = slots.next_after(cursor) {
        cursor = Some(id);
        let slot = slots.get(id).expect("just found");
        let run = slot
            .run
            .as_ref()
            .expect("no transfer is out while the multi is called");
        for (socket, events) in run.state.pollset(slot.pause).iter() {
            f(socket, events);
        }
    }
    for (socket, events) in set.pollsets() {
        f(socket, events);
    }
}

/// The lowest-id unread completion, marked read (`curl_multi_info_read`).
/// What the transfers in `slots` are doing, `counts` being the multi's.
/// A transfer whose run is out of its slot is being stepped or replayed:
/// it neither waits for a connection nor has completed, and is skipped.
fn census_of<H: Host>(slots: &Slots<H>, counts: Counts) -> Census {
    let (mut pending, mut unread) = (0, 0);
    let mut cursor = None;
    while let Some(id) = slots.next_after(cursor) {
        cursor = Some(id);
        let Some(run) = &slots.get(id).expect("just found").run else {
            continue;
        };
        match &run.state {
            TransferState::Pending(_) => pending += 1,
            TransferState::Completed(c) if c.message == MessageState::Unread => unread += 1,
            _ => {}
        }
    }
    Census {
        counts,
        pending,
        unread,
    }
}

fn read_message<H: Host>(slots: &mut Slots<H>) -> Option<Message<'_, H>> {
    let mut found = None;
    let mut remaining = 0;
    let mut cursor = None;
    while let Some(id) = slots.next_after(cursor) {
        cursor = Some(id);
        if let TransferState::Completed(c) = &run_in(slots, id).state
            && c.message == MessageState::Unread
        {
            if found.is_none() {
                found = Some(id);
            } else {
                remaining += 1;
            }
        }
    }
    let id = found?;
    let slot = slots.get_mut(id).expect("just found");
    let run = slot
        .run
        .as_mut()
        .expect("no transfer is out while the multi is called");
    let TransferState::Completed(c) = &mut run.state else {
        unreachable!("just found completed");
    };
    c.message = MessageState::Read;
    Some(Message {
        id,
        owner: &slot.owner,
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
    let Some(slot) = rest.tell.slots.get_mut(id) else {
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
    let unpaused = (was.send == SendPause::Asked && slot.pause.send == SendPause::Running)
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
    let replay = if was_held && slot.pause.recv == RecvPause::Running {
        slot.run.take()
    } else {
        None
    };
    if let Some(readers) = unpaused {
        let mut cx = StepCx::new(id, rest.reborrow());
        readers.trace_unpause(&mut cx);
    }
    if let Some(mut run) = replay {
        let mut cx = StepCx::new(id, rest.reborrow());
        let replayed = state::flush(&mut run, &mut cx);
        put_back(rest.tell.slots, rest.dirty, id, run);
        return replayed;
    }
    Ok(())
}

/// The TLS library's objects of the connection transfer `id`, whose run
/// is in its slot, holds.
fn tls_native_in<H: Host>(slots: &Slots<H>, id: TransferId) -> Option<TlsNative> {
    slots.get(id)?.run.as_ref()?.state.tls_native()
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
        let now = self.clock.now();
        let max_total = self.limits.max_total;
        {
            let tell = Telling {
                slots: &mut self.slots,
                limits: &mut self.limits,
                notify: &mut self.notify,
                counts: &self.counts,
                sockets: &mut self.sockets,
                life: &mut self.life,
            };
            let mut net = Announcing::multi(&mut *self.net, tell, &mut *ev);
            let mut exits = WithSet {
                net: &mut net,
                set: &mut self.shutdowns,
                max_total,
                multi_pool: None,
            };
            self.caches.pool.close_idle(&mut exits, now);
        }
        let mut tell = Telling {
            slots: &mut self.slots,
            limits: &mut self.limits,
            notify: &mut self.notify,
            counts: &self.counts,
            sockets: &mut self.sockets,
            life: &mut self.life,
        };
        cx::announce_closing(&mut self.shutdowns, &mut *self.net, &mut tell, &mut *ev);
        if self.shutdowns.is_empty() {
            return;
        }
        let limit = graceful_shutdown();
        let mut net = Announcing::multi(&mut *self.net, tell, ev);
        // `cshutdn_terminate_all`: a pass, then a wait for its sockets,
        // until all are done or the time is spent.
        loop {
            self.shutdowns.perform(&mut net, self.clock.now());
            if self.shutdowns.is_empty() {
                break;
            }
            let spent = self.clock.now().since(now);
            if spent >= limit {
                break;
            }
            let wait = (limit - spent).min(Duration::from_secs(1));
            if wait_for(&self.shutdowns, &mut net, wait).is_err() {
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
mod props;
#[cfg(test)]
mod shutdown_tests;
#[cfg(test)]
mod socket_tests;
#[cfg(test)]
mod tests;
