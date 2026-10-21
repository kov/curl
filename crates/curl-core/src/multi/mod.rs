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
mod notify;
mod sched;
pub(crate) mod state;
mod timers;
mod wait;

use std::time::Duration;

use curl_alloc::{OutOfMemory, TryArc, try_box};

use crate::conn::Pool;
use crate::conn::io::{Net, Waker};
use crate::deliver::{Pause, RecvPause};
use crate::easy::Easy;
use crate::error::{ErrorKind, MultiErrorKind};
use crate::id::{Arena, ArenaPolicy, Key};
use crate::progress::Speedometer;
use crate::time::{Clock, Instant};

pub use crate::deliver::PauseRequest;
use cx::EngineRest;
pub use cx::{EventCx, NotifyCx, TransferCx};
pub use notify::{Notification, NotifyKind};
pub use sched::Counts;
pub use timers::TimerChange;
pub use wait::{WaitMode, drive_to_completion};

use notify::NotifyQueue;
use sched::{RowSet, Tally};
use state::{Message as MessageState, Run, StepCx, TransferState, Wake};
use timers::{Due, TimerAnnounce, TimerQueue};

/// The application's types a multi carries: a value per transfer, handed
/// back with its messages and on removal.
pub trait Host {
    type Transfer;
}

/// A multi that carries nothing for the application.
#[derive(Debug)]
pub struct NoHost;

impl Host for NoHost {
    type Transfer = ();
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

    /// Whether `timer` is wanted. Without it the multi keeps no record of
    /// what it announced, as C without a timer callback.
    fn wants_timer(&self) -> bool {
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
    pub net: Box<dyn Net>,
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
    easy: Easy,
    /// Reachable while the run is out, for the transfer's own handlers.
    pause: Pause,
    /// Beside the pause, which starts it over.
    speedometer: Speedometer,
    /// Out only while the transfer is being stepped.
    run: Option<Box<Run>>,
}

/// An `Easy` the multi did not take, and why.
#[derive(Debug)]
pub struct AddError {
    pub kind: MultiErrorKind,
    pub easy: Easy,
}

/// A transfer taken out of the multi.
#[derive(Debug)]
pub struct Removed<H: Host> {
    pub easy: Easy,
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
}

pub struct Multi<H: Host = NoHost> {
    slots: Arena<Slot<H>, Transfer>,
    dirty: RowSet,
    timers: TimerQueue<Transfer>,
    announce: TimerAnnounce,
    notify: NotifyQueue,
    /// Notifications are being delivered.
    delivering: bool,
    pool: Pool,
    clock: Box<dyn Clock>,
    net: Box<dyn Net>,
    waker: Option<TryArc<Waker>>,
    counts: Tally,
    life: Life,
    /// A transfer was told the library is a debug build.
    #[cfg(feature = "debug-hooks")]
    warned: bool,
}

impl<H: Host> Multi<H> {
    pub fn new(env: Env) -> Result<Self, OutOfMemory> {
        Ok(Multi {
            slots: Arena::new(env.arena)?,
            dirty: RowSet::default(),
            timers: TimerQueue::new(),
            announce: TimerAnnounce::default(),
            notify: NotifyQueue::default(),
            delivering: false,
            pool: Pool::new()?,
            clock: env.clock,
            net: env.net,
            waker: env.waker,
            counts: Tally::default(),
            life: Life::Alive,
            #[cfg(feature = "debug-hooks")]
            warned: false,
        })
    }

    /// Add a transfer, to run at the next `perform` (`curl_multi_add_handle`).
    /// Everything the transfer can need from the multi's tables is
    /// reserved here, so running it allocates nothing in them.
    #[expect(
        clippy::result_large_err,
        reason = "the refused Easy comes back by value: boxing it would allocate when memory ran out"
    )]
    pub fn add(
        &mut self,
        easy: Easy,
        owner: H::Transfer,
        ev: &mut dyn MultiEvents<H>,
    ) -> Result<TransferId, AddError> {
        let added = self.add_unchecked(easy, owner, ev);
        self.check();
        added
    }

    #[expect(
        clippy::result_large_err,
        reason = "the refused Easy comes back by value: boxing it would allocate when memory ran out"
    )]
    fn add_unchecked(
        &mut self,
        easy: Easy,
        owner: H::Transfer,
        ev: &mut dyn MultiEvents<H>,
    ) -> Result<TransferId, AddError> {
        #[expect(
            clippy::result_large_err,
            reason = "the refused Easy comes back by value: boxing it would allocate when memory ran out"
        )]
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
        let Ok(run) = try_box(Run::new(self.clock.now())) else {
            return refuse(MultiErrorKind::OutOfMemory, easy);
        };
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
        #[cfg(feature = "debug-hooks")]
        let run = {
            let mut run = run;
            run.warn = !self.warned;
            self.warned = true;
            run
        };
        let id = vacancy.fill(Slot {
            owner,
            easy,
            pause: Pause::default(),
            speedometer: Speedometer::default(),
            run: Some(run),
        });
        self.counts.added();
        self.pool.xfer_init();
        self.dirty.insert(id.index());
        // Inside the add, as C, so the application hears of the 0 ms run.
        if let Err(kind) = self.update_timer(ev) {
            let slot = self.slots.remove(id).expect("just added");
            self.dirty.remove(id.index());
            self.counts.add_undone();
            return refuse(kind, slot.easy);
        }
        Ok(id)
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
        let mut slot = self.slots.remove(id)?;
        let run = slot
            .run
            .take()
            .expect("no transfer is out while the multi is called");
        self.counts.removed(run.state.is_completed());
        let now = self.clock.now();
        run.state.abandon(&mut self.pool, &mut *self.net, now);
        self.timers.remove(id);
        self.dirty.remove(id.index());
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
        let mut cursor = None;
        while let Some(id) = self.slots.next_after(cursor) {
            cursor = Some(id);
            self.run_single(id, now);
        }
        self.dispatch(ev);
        // Timers due by the pass's start have been dealt with.
        while let Some(id) = self.timers.pop_due(now) {
            self.requeue_after_expiry(id, now);
        }
        self.update_timer(ev)?;
        Ok(self.counts.get().running)
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
        }
        let now = self.clock.now();
        self.mark_expired_dirty(now);
        if self.run_dirty(now) > 0 {
            // Running took time: catch what came due meanwhile, once.
            let now = self.clock.now();
            self.mark_expired_dirty(now);
            self.run_dirty(now);
        }
        self.dispatch(ev);
        self.update_timer(ev)?;
        Ok(self.counts.get().running)
    }

    /// The oldest-added unread completion, marked read
    /// (`curl_multi_info_read`).
    pub fn info_read(&mut self) -> Option<Message<'_, H>> {
        read_message(&mut self.slots)
    }

    /// How many completed transfers' messages are unread
    /// (`CURLMINFO_XFERS_DONE`).
    pub fn unread(&self) -> u32 {
        let mut unread = 0;
        let mut cursor = None;
        while let Some(id) = self.slots.next_after(cursor) {
            cursor = Some(id);
            if let Some(run) = &self.slots.get(id).expect("just found").run
                && let TransferState::Completed(c) = &run.state
                && c.message == MessageState::Unread
            {
                unread += 1;
            }
        }
        unread
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
        let mut rest = EngineRest {
            slots: &mut self.slots,
            pool: &mut self.pool,
            net: &mut *self.net,
            dirty: &mut self.dirty,
            now,
        };
        let result = pause_transfer(&mut rest, id, req);
        // The timer hears only of a change: one that leaves the transfer
        // running, which it marks dirty (easy.c:1229).
        let timer = self
            .update_timer(ev)
            .map_err(|_| ErrorKind::AbortedByCallback);
        self.check();
        result.and(timer)
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
        self.slots.get(id).map(|s| &s.easy)
    }

    pub fn easy_mut(&mut self, id: TransferId) -> Option<&mut Easy> {
        self.slots.get_mut(id).map(|s| &mut s.easy)
    }

    fn run_of(&self, id: TransferId) -> &Run {
        run_in(&self.slots, id)
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
        let mut cx = StepCx {
            me: id,
            rest: EngineRest {
                slots: &mut self.slots,
                pool: &mut self.pool,
                net: &mut *self.net,
                dirty: &mut self.dirty,
                now,
            },
        };
        let r = f(&mut cx);
        self.slots.get_mut(id).expect("still in the multi").run = run;
        r
    }

    fn run_single(&mut self, id: TransferId, now: Instant) {
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
        let mut cx = StepCx {
            me: id,
            rest: EngineRest {
                slots: &mut self.slots,
                pool: &mut self.pool,
                net: &mut *self.net,
                dirty: &mut self.dirty,
                now,
            },
        };
        while state::step(&mut run, &mut cx) == Wake::Again {}
        let completed = run.state.is_completed();
        if completed {
            self.counts.completed();
            run.deadlines.clear_all();
            self.timers.remove(id);
        } else {
            self.timers.update(id, run.deadlines.wake_at());
        }
        self.slots.get_mut(id).expect("still in the multi").run = Some(run);
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
    fn run_dirty(&mut self, now: Instant) -> u32 {
        let mut ran = 0;
        let mut from = 0;
        while let Some(row) = self.dirty.first_from(from) {
            from = row + 1;
            let Some(id) = self.slots.key_at(row) else {
                self.dirty.remove(row);
                continue;
            };
            if self.run_of(id).state.is_completed() {
                self.dirty.remove(row);
                continue;
            }
            ran += 1;
            self.run_single(id, now);
        }
        ran
    }

    /// Mark every transfer with a timer due by `now` dirty
    /// (`multi_mark_expired_as_dirty`).
    fn mark_expired_dirty(&mut self, now: Instant) {
        while let Some(id) = self.timers.pop_due(now) {
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
        if self.life == Life::Dead || self.dirty.first_from(0).is_some() {
            return Due::Now;
        }
        match self.timers.peek() {
            Some((at, _)) => Due::At(at),
            None => Due::Never,
        }
    }

    /// Tell the application's timer of a change (`Curl_update_timer`). An
    /// abort kills the multi.
    fn update_timer(&mut self, ev: &mut dyn MultiEvents<H>) -> Result<(), MultiErrorKind> {
        if !ev.wants_timer() || self.life == Life::Dead {
            return Ok(());
        }
        let Some(change) = self.announce.update(self.clock.now(), self.due()) else {
            return Ok(());
        };
        let mut cx = EventCx {
            slots: &mut self.slots,
            notify: &mut self.notify,
            counts: self.counts.get(),
        };
        ev.timer(&mut cx, change).map_err(|Abort| {
            self.life = Life::Dead;
            MultiErrorKind::AbortedByCallback
        })
    }
}

/// The lowest-id unread completion, marked read (`curl_multi_info_read`).
fn read_message<H: Host>(slots: &mut Arena<Slot<H>, Transfer>) -> Option<Message<'_, H>> {
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

fn run_in<H: Host>(slots: &Arena<Slot<H>, Transfer>, id: TransferId) -> &Run {
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
    let Some(slot) = rest.slots.get_mut(id) else {
        return Err(ErrorKind::BadFunctionArgument);
    };
    // A run out of its slot is delivering output, so it has a connection.
    if slot.run.as_ref().is_some_and(|r| !r.state.holds_lease()) {
        return Err(ErrorKind::BadFunctionArgument);
    }
    let was = slot.pause;
    let was_held = was.recv == RecvPause::Held;
    slot.pause.apply(req);
    // A direction that goes on measures its speed afresh.
    if (was.recv_paused() && !slot.pause.recv_paused())
        || (was.send_paused() && !slot.pause.send_paused())
    {
        slot.speedometer.start_over();
    }
    // Unless paused every way it wants (judged on receiving alone until
    // the pollset knows the directions, step 11), the transfer runs again,
    // and is not slow for the time it was not.
    if !slot.pause.recv_paused() {
        slot.speedometer.forget_slow();
        rest.dirty.insert(id.index());
    }
    if was_held
        && slot.pause.recv == RecvPause::Running
        && let Some(mut run) = slot.run.take()
    {
        let mut cx = StepCx {
            me: id,
            rest: EngineRest {
                slots: &mut *rest.slots,
                pool: &mut *rest.pool,
                net: &mut *rest.net,
                dirty: &mut *rest.dirty,
                now: rest.now,
            },
        };
        let replayed = state::flush(&mut run, &mut cx);
        rest.slots.get_mut(id).expect("still in the multi").run = Some(run);
        return replayed;
    }
    Ok(())
}

impl<H: Host> Drop for Multi<H> {
    /// Take out every transfer still in the multi, giving back its
    /// connection (`curl_multi_cleanup`).
    fn drop(&mut self) {
        let now = self.clock.now();
        let mut cursor = None;
        while let Some(id) = self.slots.next_after(cursor) {
            cursor = Some(id);
            let slot = self.slots.get_mut(id).expect("just found");
            if let Some(run) = slot.run.take() {
                run.state.abandon(&mut self.pool, &mut *self.net, now);
            }
        }
        self.pool.close_idle(&mut *self.net);
    }
}

#[cfg(test)]
mod props;
#[cfg(test)]
mod tests;
