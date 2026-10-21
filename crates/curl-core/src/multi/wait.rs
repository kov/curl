//! Waiting for the multi's sockets, the application's descriptors and
//! wakes from other threads (`multi_wait`), and driving one transfer to its
//! end over those waits (`easy_transfer`), or over what the multi tells its
//! timer and socket callbacks (`easy_events`).

use std::time::Duration;

use curl_alloc::{TryArc, TryVec};

use super::state::{Message as MessageState, TransferState};
use super::{
    Abort, EventCx, Host, Multi, MultiEvents, SocketEvent, SocketWhat, TimerChange, TransferId,
    pollsets,
};
use crate::conn::io::{Events, PollFd, Socket, SocketKey, SocketPoll, Waker};
use crate::error::{ErrorKind, MultiErrorKind};

/// How `wait` treats a multi with nothing to wait for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WaitMode {
    /// Return at once (`curl_multi_wait`).
    Wait,
    /// Sleep for the timeout anyway, unless woken (`curl_multi_poll`).
    Poll,
}

impl<H: Host> Multi<H> {
    /// Wait for the multi's sockets or `extra` to be ready, for at most
    /// `max` and no longer than the multi's own timeout
    /// (`curl_multi_wait`, `curl_multi_poll`). Returns how many had events;
    /// `extra`'s are left in its entries. A wake from another thread ends
    /// the wait without counting.
    pub fn wait(
        &mut self,
        extra: &mut [PollFd<'_>],
        max: Duration,
        mode: WaitMode,
    ) -> Result<u32, MultiErrorKind> {
        let timeout = self.timeout().map_or(max, |t| t.min(max));
        let mut wanted = 0;
        pollsets(&self.slots, &self.caches.pool, |_, _| wanted += 1);
        let mut sockets = Vec::new();
        sockets
            .try_reserve_exact(wanted)
            .map_err(|_| MultiErrorKind::OutOfMemory)?;
        pollsets(&self.slots, &self.caches.pool, |s, events| {
            sockets
                .try_push(SocketPoll::new(s, events))
                .expect("reserved");
        });
        // The waker is watched when the wait will be one (multi.c:1574).
        let watch_waker = mode == WaitMode::Poll || !sockets.is_empty() || !extra.is_empty();
        let waker = self.waker.as_deref().filter(|_| watch_waker);
        let mut fds = Vec::new();
        fds.try_reserve_exact(extra.len() + usize::from(waker.is_some()))
            .map_err(|_| MultiErrorKind::OutOfMemory)?;
        for fd in extra.iter() {
            fds.try_push(*fd).expect("reserved");
        }
        if let Some(w) = waker {
            fds.try_push(PollFd::new(w.fd(), Events::IN))
                .expect("reserved");
        }
        if sockets.is_empty() && fds.is_empty() && mode == WaitMode::Wait {
            return Ok(0);
        }
        let mut ready = self
            .net
            .poll(&mut sockets, &mut fds, timeout)
            .map_err(|_| MultiErrorKind::UnrecoverablePoll)?;
        for (mine, polled) in extra.iter_mut().zip(&fds) {
            mine.copy_revents(polled);
        }
        if let Some(w) = waker
            && fds[extra.len()].revents().contains(Events::IN)
        {
            // Draining is best effort: a wake left behind only ends the
            // next wait early.
            let _ = w.drain();
            ready -= 1;
        }
        Ok(ready)
    }

    /// Wait up to `timeout`, or for as long as it takes, for the sockets
    /// `watched` names to be ready, each for its events, and give those
    /// that are, in `watched`'s order. Each is a socket a transfer waits
    /// on, as the multi says REMOVE before one closes. With none watched,
    /// sleep for `timeout`, if there is one.
    fn poll_watched(
        &mut self,
        watched: &[(SocketKey, Events)],
        timeout: Option<Duration>,
    ) -> Result<Vec<SocketKey>, MultiErrorKind> {
        let oom = |_| MultiErrorKind::OutOfMemory;
        let mut found: Vec<Option<&dyn Socket>> = Vec::new();
        found.try_reserve_exact(watched.len()).map_err(oom)?;
        for _ in watched {
            found.try_push(None).expect("reserved");
        }
        pollsets(&self.slots, &self.caches.pool, |s, _| {
            let key = s.key();
            if let Some(at) = watched.iter().position(|&(k, _)| k == key) {
                found[at].get_or_insert(s);
            }
        });
        let mut sockets = Vec::new();
        sockets.try_reserve_exact(watched.len()).map_err(oom)?;
        for (s, &(key, events)) in found.iter().zip(watched) {
            let s = s.unwrap_or_else(|| panic!("socket {key:?} was watched after its REMOVE"));
            sockets
                .try_push(SocketPoll::new(s, events))
                .expect("reserved");
        }
        let mut ready = Vec::new();
        if sockets.is_empty() {
            if let Some(t) = timeout.filter(|t| !t.is_zero()) {
                self.net
                    .poll(&mut [], &mut [], t)
                    .map_err(|_| MultiErrorKind::UnrecoverablePoll)?;
            }
            return Ok(ready);
        }
        self.net
            .poll(&mut sockets, &mut [], timeout.unwrap_or(Duration::MAX))
            .map_err(|_| MultiErrorKind::UnrecoverablePoll)?;
        for (s, &(key, _)) in sockets.iter().zip(watched) {
            if !s.revents().is_empty() {
                ready
                    .try_push(key)
                    .map_err(|_| MultiErrorKind::OutOfMemory)?;
            }
        }
        Ok(ready)
    }

    /// The waker that ends this multi's waits from another thread
    /// (`curl_multi_wakeup`).
    pub fn waker(&self) -> Option<TryArc<Waker>> {
        self.waker.clone()
    }

    /// A completed transfer's result, its message marked read; `None`
    /// while it runs. Other transfers' messages stay unread.
    fn take_outcome(&mut self, id: TransferId) -> Option<Result<(), ErrorKind>> {
        let run = self.slots.get_mut(id)?.run.as_mut()?;
        let TransferState::Completed(c) = &mut run.state else {
            return None;
        };
        c.message = MessageState::Read;
        Some(c.outcome)
    }
}

/// Drive `m` until transfer `id` completes, and return its result with its
/// message read (`easy_transfer`): wait for at most a second, run, and
/// again. Other transfers run meanwhile and keep their messages. A transfer
/// not in the multi, or taken out of it meanwhile, is `BadEasyHandle`.
pub fn drive_to_completion<H: Host>(
    m: &mut Multi<H>,
    id: TransferId,
    ev: &mut dyn MultiEvents<H>,
) -> Result<Result<(), ErrorKind>, MultiErrorKind> {
    loop {
        // Checked on every round, as a callback may take it out.
        if m.slots.get(id).is_none() {
            return Err(MultiErrorKind::BadEasyHandle);
        }
        m.wait(&mut [], Duration::from_secs(1), WaitMode::Poll)?;
        m.perform(ev)?;
        if let Some(outcome) = m.take_outcome(id) {
            return Ok(outcome);
        }
    }
}

/// What `drive_by_events` watches: what the multi last told its timer and
/// socket callbacks (C's `struct events`, kept for one call rather than
/// for the process).
#[derive(Debug, Default)]
struct EventTable {
    /// How long to wait for a socket, less what was spent since it was
    /// set; `None` for as long as it takes.
    wait: Option<Duration>,
    /// The timer was set since the last wait (`msbump`).
    bumped: bool,
    /// The sockets to watch and for what, the newest last.
    sockets: Vec<(SocketKey, Events)>,
}

impl<H: Host> MultiEvents<H> for EventTable {
    fn timer(&mut self, _: &mut EventCx<'_, H>, change: TimerChange) -> Result<(), Abort> {
        self.wait = match change {
            TimerChange::Set(d) => Some(d),
            TimerChange::Clear => None,
        };
        self.bumped = true;
        Ok(())
    }

    fn wants_timer(&self) -> bool {
        true
    }

    /// `events_socket`.
    fn socket(
        &mut self,
        _: &mut EventCx<'_, H>,
        _: TransferId,
        s: SocketKey,
        what: SocketWhat,
        _: Option<H::Socket>,
    ) -> Result<(), Abort> {
        let events = match what {
            SocketWhat::In => Events::IN,
            SocketWhat::Out => Events::OUT,
            SocketWhat::InOut => Events::IN | Events::OUT,
            SocketWhat::Remove => Events::NONE,
        };
        match self.sockets.iter().position(|&(k, _)| k == s) {
            Some(at) if what == SocketWhat::Remove => {
                self.sockets.remove(at);
            }
            Some(at) => self.sockets[at].1 = events,
            None => {
                assert!(
                    what != SocketWhat::Remove,
                    "socket {s:?} removed but never added"
                );
                // A table that cannot grow fails the call, as C's
                // callback does.
                self.sockets.try_push((s, events)).map_err(|_| Abort)?;
            }
        }
        Ok(())
    }

    fn wants_sockets(&self) -> bool {
        true
    }
}

/// Drive `m` until transfer `id` completes, as `drive_to_completion` does,
/// but through `socket_action` alone, watching only what the multi tells
/// its timer and socket callbacks (`easy_events`, the debug build's
/// `curl_easy_perform_ev`). A failure of the multi's own is the
/// transfer's `UrlMalformat`, as C makes it.
pub fn drive_by_events<H: Host>(
    m: &mut Multi<H>,
    id: TransferId,
) -> Result<Result<(), ErrorKind>, MultiErrorKind> {
    let mut table = EventTable::default();
    loop {
        // Checked on every round, as a callback may take it out.
        if m.slots.get(id).is_none() {
            return Err(MultiErrorKind::BadEasyHandle);
        }
        let start = m.clock.now();
        let mut ready = match m.poll_watched(&table.sockets, table.wait) {
            Ok(ready) => ready,
            Err(MultiErrorKind::OutOfMemory) => return Ok(Err(ErrorKind::OutOfMemory)),
            Err(_) => return Ok(Err(ErrorKind::UnrecoverablePoll)),
        };
        table.bumped = false;
        let acted = if ready.is_empty() {
            // The timer ran out, and none is set until the multi says: it
            // tells every wait after a timeout, so saying nothing means
            // nothing is due. C sets 0 here, and polls without waiting
            // until a socket is ready when nothing was ever due.
            table.wait = None;
            m.socket_action(SocketEvent::Timeout, &mut table)
        } else {
            // The newest first, as C's list keeps them; C keeps the last
            // call's result.
            ready.reverse();
            let mut acted = Ok(0);
            for key in ready {
                acted = m.socket_action(SocketEvent::Socket(key), &mut table);
            }
            // A timer not set again counts down by the time spent.
            if !table.bumped
                && let Some(wait) = table.wait
            {
                table.wait = Some(wait.saturating_sub(m.clock.now().since(start)));
            }
            acted
        };
        if acted.is_err() {
            return Ok(Err(ErrorKind::UrlMalformat));
        }
        if let Some(outcome) = m.take_outcome(id) {
            return Ok(outcome);
        }
    }
}
