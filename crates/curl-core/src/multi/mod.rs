//! The multi: transfers driven together, as libcurl's multi handle drives
//! them (`lib/multi.c`).
//!
//! A multi owns its transfers, their connections and its clock. The
//! application adds an `Easy`, drives the multi with `perform` or
//! `socket_action`, reads completions with `info_read`, and gets the
//! `Easy` back with `remove`. It learns when to drive the multi next
//! through the timer events of its `MultiEvents`.

mod sched;
mod state;
mod timers;

use std::time::Duration;

use curl_alloc::{OutOfMemory, try_box};

use crate::conn::Pool;
use crate::easy::Easy;
use crate::error::{ErrorKind, MultiErrorKind};
use crate::id::{Arena, ArenaPolicy, Key};
use crate::time::{Clock, Instant};

pub use sched::Counts;
pub use timers::TimerChange;

use sched::RowSet;
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
    fn timer(&mut self, change: TimerChange) -> Result<(), Abort> {
        let _ = change;
        Ok(())
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

/// How a multi is made: its clock and the ids it hands out.
pub struct Env {
    pub clock: Box<dyn Clock>,
    pub arena: ArenaPolicy,
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
    pool: Pool,
    clock: Box<dyn Clock>,
    counts: Counts,
    life: Life,
}

impl<H: Host> Multi<H> {
    pub fn new(env: Env) -> Result<Self, OutOfMemory> {
        Ok(Multi {
            slots: Arena::new(env.arena)?,
            dirty: RowSet::default(),
            timers: TimerQueue::new(),
            announce: TimerAnnounce::default(),
            pool: Pool::new()?,
            clock: env.clock,
            counts: Counts::default(),
            life: Life::Alive,
        })
    }

    /// Add a transfer, to run at the next `perform` (`curl_multi_add_handle`).
    /// Everything the transfer can need from the multi's tables is
    /// reserved here, so running it allocates nothing in them.
    pub fn add(
        &mut self,
        easy: Easy,
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
        let Ok(run) = try_box(Run::new(self.clock.now())) else {
            return refuse(MultiErrorKind::OutOfMemory, easy);
        };
        let Ok(vacancy) = self.slots.reserve() else {
            return refuse(MultiErrorKind::OutOfMemory, easy);
        };
        let rows = vacancy.rows();
        if self.timers.reserve(rows).is_err() || self.dirty.reserve(rows).is_err() {
            return refuse(MultiErrorKind::OutOfMemory, easy);
        }
        let id = vacancy.fill(Slot {
            owner,
            easy,
            run: Some(run),
        });
        self.counts.running += 1;
        self.counts.current += 1;
        self.counts.added_ever += 1;
        self.dirty.insert(id.index());
        // Inside the add, as C, so the application hears of the 0 ms run.
        if let Err(kind) = self.update_timer(ev) {
            let slot = self.slots.remove(id).expect("just added");
            self.dirty.remove(id.index());
            self.counts.running -= 1;
            self.counts.current -= 1;
            return refuse(kind, slot.easy);
        }
        Ok(id)
    }

    /// Take a transfer out, completed or not, and give its `Easy` back
    /// (`curl_multi_remove_handle`). `None` if `id` is not in this multi.
    /// A transfer that had not completed gives its connection back as a
    /// premature end, and leaves no message.
    pub fn remove(&mut self, id: TransferId, ev: &mut dyn MultiEvents<H>) -> Option<Removed<H>> {
        let mut slot = self.slots.remove(id)?;
        let run = slot
            .run
            .take()
            .expect("no transfer is out while the multi is called");
        if !run.state.is_completed() {
            self.counts.running -= 1;
        }
        self.counts.current -= 1;
        run.state.abandon(&mut self.pool);
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
        let now = self.clock.now();
        let mut cursor = None;
        while let Some(id) = self.slots.next_after(cursor) {
            cursor = Some(id);
            self.run_single(id, now);
        }
        // Timers due by the pass's start have been dealt with.
        while let Some(id) = self.timers.pop_due(now) {
            self.requeue_after_expiry(id, now);
        }
        self.update_timer(ev)?;
        Ok(self.counts.running)
    }

    /// Run the transfers an event concerns (`curl_multi_socket_action`).
    pub fn socket_action(
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
        self.update_timer(ev)?;
        Ok(self.counts.running)
    }

    /// The oldest-added unread completion, marked read
    /// (`curl_multi_info_read`).
    pub fn info_read(&mut self) -> Option<Message<'_, H>> {
        let mut found = None;
        let mut remaining = 0;
        let mut cursor = None;
        while let Some(id) = self.slots.next_after(cursor) {
            cursor = Some(id);
            if let TransferState::Completed(c) = &self.run_of(id).state
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
        let slot = self.slots.get_mut(id).expect("just found");
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
        self.counts
    }

    pub fn easy(&self, id: TransferId) -> Option<&Easy> {
        self.slots.get(id).map(|s| &s.easy)
    }

    pub fn easy_mut(&mut self, id: TransferId) -> Option<&mut Easy> {
        self.slots.get_mut(id).map(|s| &mut s.easy)
    }

    fn run_of(&self, id: TransferId) -> &Run {
        let slot = self.slots.get(id).expect("a transfer in the multi");
        slot.run
            .as_ref()
            .expect("no transfer is out while the multi is called")
    }

    /// Step one transfer until it waits (`multi_runsingle`).
    fn run_single(&mut self, id: TransferId, now: Instant) {
        self.dirty.remove(id.index());
        let slot = self.slots.get_mut(id).expect("a transfer in the multi");
        if slot.run.as_ref().is_some_and(|r| r.state.is_completed()) {
            return;
        }
        let mut run = slot.run.take().expect("not already out");
        if self.life == Life::Dead {
            // A callback aborted the multi: every transfer fails.
            run.state = std::mem::replace(&mut run.state, TransferState::Init)
                .fail(ErrorKind::AbortedByCallback);
        }
        let mut cx = StepCx {
            easy: &slot.easy,
            pool: &mut self.pool,
            now,
        };
        while state::step(&mut run, &mut cx) == Wake::Again {}
        if run.state.is_completed() {
            self.counts.running -= 1;
            run.deadlines.clear_all();
            self.timers.remove(id);
        } else {
            self.timers.update(id, run.deadlines.wake_at());
        }
        slot.run = Some(run);
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
        ev.timer(change).map_err(|Abort| {
            self.life = Life::Dead;
            MultiErrorKind::AbortedByCallback
        })
    }
}

impl<H: Host> Drop for Multi<H> {
    /// Take out every transfer still in the multi, giving back its
    /// connection (`curl_multi_cleanup`).
    fn drop(&mut self) {
        let mut cursor = None;
        while let Some(id) = self.slots.next_after(cursor) {
            cursor = Some(id);
            let slot = self.slots.get_mut(id).expect("just found");
            if let Some(run) = slot.run.take() {
                run.state.abandon(&mut self.pool);
            }
        }
    }
}

#[cfg(test)]
mod tests;
