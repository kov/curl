//! Waiting for the multi's sockets, the application's descriptors and
//! wakes from other threads (`multi_wait`), and driving one transfer to its
//! end over those waits (`easy_transfer`), or over what the multi tells its
//! timer and socket callbacks (`easy_events`).

use std::os::fd::AsRawFd as _;
use std::time::Duration;

use curl_alloc::{TryArc, TryVec};

use super::state::StepCx;
use super::state::{Message as MessageState, TransferState};
use super::{
    Abort, EventCx, Host, Multi, MultiEvents, SocketEvent, SocketWhat, TimerChange, TransferId,
    mstate, pollsets,
};
use crate::conn::io::{Events, ON_STACK, PollFd, Socket, SocketKey, SocketPoll, Waker};
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
    /// the wait without counting. Traced as C's `multi_wait`: each
    /// pollset as it is collected, then the multi's own timeout, then the
    /// wait itself on the last transfer whose pollset was.
    pub fn wait(
        &mut self,
        extra: &mut [PollFd<'_>],
        max: Duration,
        mode: WaitMode,
        ev: &mut dyn MultiEvents<H>,
    ) -> Result<u32, MultiErrorKind> {
        let now = self.clock.now();
        let last = self.trace_pollsets(now, ev);
        // After the pollsets, which may arm timers (multi.c:1602).
        let internal = self.multi_timeout(now, ev);
        let timeout = internal.map_or(max, |t| t.min(max));
        let mut wanted = 0;
        pollsets(&self.slots, &self.caches.pool, &self.shutdowns, |_, _| {
            wanted += 1
        });
        // The resolver's wake, listened on while a transfer is alive, is
        // one of the multi's own (C's admin handle's pollset).
        let resolver_waker = self.alive.waker.clone().filter(|_| self.alive.count > 0);
        let resolver = resolver_waker
            .as_deref()
            .map(|w| PollFd::new(w.fd(), Events::IN));
        wanted += usize::from(resolver.is_some());
        // The waker is watched when the wait will be one (multi.c:1574).
        let watch_waker = mode == WaitMode::Poll || wanted > 0 || !extra.is_empty();
        let waker_watched = self.waker.is_some() && watch_waker;
        if let Some(id) = last {
            let fds = wanted + usize::from(waker_watched) + extra.len();
            self.trace_wait(id, now, fds, timeout, internal, ev);
        }
        let oom = |_| MultiErrorKind::OutOfMemory;
        // A few entries are kept on the stack, more in memory of their
        // own, as C's `a_few_on_stack`: a loop of waits allocates nothing.
        let mut first = None;
        pollsets(
            &self.slots,
            &self.caches.pool,
            &self.shutdowns,
            |s, events| {
                first.get_or_insert((s, events));
            },
        );
        let mut few_sockets;
        let mut more_sockets = Vec::new();
        let sockets: &mut [SocketPoll<'_>] = match first {
            None => &mut [],
            Some((s, events)) if wanted <= ON_STACK => {
                few_sockets = [(); ON_STACK].map(|()| SocketPoll::new(s, events));
                let mut at = 0;
                pollsets(
                    &self.slots,
                    &self.caches.pool,
                    &self.shutdowns,
                    |s, events| {
                        few_sockets[at] = SocketPoll::new(s, events);
                        at += 1;
                    },
                );
                &mut few_sockets[..wanted]
            }
            Some(_) => {
                more_sockets.try_reserve_exact(wanted).map_err(oom)?;
                pollsets(
                    &self.slots,
                    &self.caches.pool,
                    &self.shutdowns,
                    |s, events| {
                        more_sockets
                            .try_push(SocketPoll::new(s, events))
                            .expect("reserved");
                    },
                );
                &mut more_sockets
            }
        };
        let waker = self
            .waker
            .as_deref()
            .filter(|_| waker_watched)
            .map(|w| (w, PollFd::new(w.fd(), Events::IN)));
        // The application's, then the resolver's, then the waker's.
        let resolver_at = extra.len();
        let waker_at = resolver_at + usize::from(resolver.is_some());
        let n_fds = waker_at + usize::from(waker.is_some());
        let mut few_fds;
        let mut more_fds = Vec::new();
        let any = extra
            .first()
            .copied()
            .or(resolver)
            .or(waker.map(|(_, fd)| fd));
        let fds: &mut [PollFd<'_>] = match any {
            None => &mut [],
            Some(any) if n_fds <= ON_STACK => {
                few_fds = [any; ON_STACK];
                few_fds[..extra.len()].copy_from_slice(extra);
                if let Some(fd) = resolver {
                    few_fds[resolver_at] = fd;
                }
                if let Some((_, fd)) = waker {
                    few_fds[waker_at] = fd;
                }
                &mut few_fds[..n_fds]
            }
            Some(_) => {
                more_fds.try_reserve_exact(n_fds).map_err(oom)?;
                more_fds.try_extend_from_slice(extra).expect("reserved");
                if let Some(fd) = resolver {
                    more_fds.try_push(fd).expect("reserved");
                }
                if let Some((_, fd)) = waker {
                    more_fds.try_push(fd).expect("reserved");
                }
                &mut more_fds
            }
        };
        let waker = waker.map(|(w, _)| w);
        if sockets.is_empty() && fds.is_empty() && mode == WaitMode::Wait {
            return Ok(0);
        }
        let mut ready = self
            .net
            .poll(sockets, fds, timeout)
            .map_err(|_| MultiErrorKind::UnrecoverablePoll)?;
        for (mine, polled) in extra.iter_mut().zip(fds.iter()) {
            mine.copy_revents(polled);
        }
        // The resolver's wake counts, as C's pollset socket does; it is
        // drained as its answers are taken.
        if let Some(w) = waker
            && fds[waker_at].revents().contains(Events::IN)
        {
            // Draining is best effort: a wake left behind only ends the
            // next wait early.
            let _ = w.drain();
            ready -= 1;
        }
        Ok(ready)
    }

    /// The wait about to be made, traced on transfer `id` (`multi_wait`):
    /// how many descriptors it polls (`fds`, the waker counted if it is
    /// watched), for how long, and the multi's own timeout, -1 for none.
    fn trace_wait(
        &mut self,
        id: TransferId,
        now: crate::time::Instant,
        fds: usize,
        timeout: Duration,
        internal: Option<Duration>,
        ev: &mut dyn MultiEvents<H>,
    ) {
        // C's milliseconds are an `int`.
        let ms = |d: Duration| i32::try_from(d.as_millis()).unwrap_or(i32::MAX);
        let (timeout, internal) = (ms(timeout), internal.map_or(-1, ms));
        let mut cx = StepCx::new(id, self.rest(now, ev));
        mstate::trace(
            &mut cx,
            format_args!("multi_wait(fds={fds}, timeout={timeout}) tinternal={internal}"),
        );
    }

    /// Wait up to `timeout`, or for as long as it takes, for the sockets
    /// `watched` names to be ready, each for its events, and give those
    /// that are, in `watched`'s order. Each is a socket a transfer waits
    /// on, as the multi says REMOVE before one closes, or the resolver's
    /// wake while a transfer is alive. With none watched, sleep for
    /// `timeout`, if there is one.
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
        pollsets(&self.slots, &self.caches.pool, &self.shutdowns, |s, _| {
            let key = s.key();
            if let Some(at) = watched.iter().position(|&(k, _)| k == key) {
                found[at].get_or_insert(s);
            }
        });
        // Watched only while the socket callback was told of it, while a
        // transfer is alive.
        let wake = self.alive.waker.as_deref();
        let wake_key = wake.map(|w| SocketKey::new(w.fd().as_raw_fd()));
        let mut wake_fd = None;
        let mut sockets = Vec::new();
        sockets.try_reserve_exact(watched.len()).map_err(oom)?;
        for (s, &(key, events)) in found.iter().zip(watched) {
            match (s, wake) {
                (Some(s), _) => sockets
                    .try_push(SocketPoll::new(*s, events))
                    .expect("reserved"),
                (None, Some(w)) if wake_key == Some(key) => {
                    wake_fd = Some(PollFd::new(w.fd(), events));
                }
                (None, _) => panic!("socket {key:?} was watched after its REMOVE"),
            }
        }
        let mut ready = Vec::new();
        if sockets.is_empty() && wake_fd.is_none() {
            if let Some(t) = timeout.filter(|t| !t.is_zero()) {
                self.net
                    .poll(&mut [], &mut [], t)
                    .map_err(|_| MultiErrorKind::UnrecoverablePoll)?;
            }
            return Ok(ready);
        }
        let fds: &mut [PollFd<'_>] = match &mut wake_fd {
            Some(fd) => std::slice::from_mut(fd),
            None => &mut [],
        };
        self.net
            .poll(&mut sockets, fds, timeout.unwrap_or(Duration::MAX))
            .map_err(|_| MultiErrorKind::UnrecoverablePoll)?;
        let mut polled = sockets.iter();
        for (s, &(key, _)) in found.iter().zip(watched) {
            let revents = match s {
                Some(_) => polled.next().expect("one polled for each found").revents(),
                None => wake_fd.as_ref().expect("the wake, if not found").revents(),
            };
            if !revents.is_empty() {
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
        m.wait(&mut [], Duration::from_secs(1), WaitMode::Poll, ev)?;
        m.perform(ev)?;
        if let Some(outcome) = m.take_outcome(id) {
            return Ok(outcome);
        }
    }
}

/// What `drive_by_events` watches: what the multi last told its timer and
/// socket callbacks (C's `struct events`). A handle's own multi keeps one
/// from a perform on, as C's callbacks stay set on it, so its cleanup's
/// changes are heard too.
#[derive(Debug, Default)]
pub(crate) struct EventTable {
    /// How long to wait for a socket, less what was spent since it was
    /// set; `None` for as long as it takes.
    wait: Option<Duration>,
    /// The timer was set since the last wait (`msbump`).
    bumped: bool,
    /// The sockets to watch and for what, the newest last.
    sockets: Vec<(SocketKey, Events)>,
    /// The multi's internal trace, which says a change to its own
    /// sockets, as C's callback traces on the handle it is given.
    internal: Option<crate::trace::Internal>,
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

    fn socket(
        &mut self,
        cx: &mut EventCx<'_, H>,
        who: super::SocketFor,
        s: SocketKey,
        what: SocketWhat,
        _: Option<H::Socket>,
    ) -> Result<(), Abort> {
        let change = self.note(s, what)?;
        let fd = s.get();
        let as_ = match what {
            SocketWhat::In => "IN",
            SocketWhat::Out => "OUT",
            SocketWhat::InOut => "INOUT",
            SocketWhat::Remove => "",
        };
        let line = match change {
            Change::Removed => format_args!("socket cb: socket {fd} REMOVED"),
            Change::Updated => format_args!("socket cb: socket {fd} UPDATED as {as_}"),
            Change::Added => format_args!("socket cb: socket {fd} ADDED as {as_}"),
        };
        // Said on the trace of the socket's owner: the transfer's, or the
        // multi's internal one (`events_socket`'s `infof(easy)`).
        match who {
            super::SocketFor::Transfer(me) => {
                crate::trace::info_outside(&mut super::cx::EventCalls { cx, me }, line);
            }
            super::SocketFor::Multi => {
                if let Some(t) = &self.internal {
                    t.info(line);
                }
            }
        }
        Ok(())
    }

    fn wants_sockets(&self) -> bool {
        true
    }
}

/// What a socket callback changed in the table.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Change {
    Added,
    Updated,
    Removed,
}

impl EventTable {
    /// Watch `s` for `what`, or stop (`events_socket`).
    fn note(&mut self, s: SocketKey, what: SocketWhat) -> Result<Change, Abort> {
        let events = match what {
            SocketWhat::In => Events::IN,
            SocketWhat::Out => Events::OUT,
            SocketWhat::InOut => Events::IN | Events::OUT,
            SocketWhat::Remove => Events::NONE,
        };
        match self.sockets.iter().position(|&(k, _)| k == s) {
            Some(at) if what == SocketWhat::Remove => {
                self.sockets.remove(at);
                Ok(Change::Removed)
            }
            Some(at) => {
                self.sockets[at].1 = events;
                Ok(Change::Updated)
            }
            None => {
                assert!(
                    what != SocketWhat::Remove,
                    "socket {s:?} removed but never added"
                );
                // A table that cannot grow fails the call, as C's
                // callback does.
                self.sockets.try_push((s, events)).map_err(|_| Abort)?;
                Ok(Change::Added)
            }
        }
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
    drive_by_events_with(m, id, &mut EventTable::default())
}

/// As `drive_by_events`, through `table`, which a multi kept from one
/// perform to the next watches across them.
pub(crate) fn drive_by_events_with<H: Host>(
    m: &mut Multi<H>,
    id: TransferId,
    table: &mut EventTable,
) -> Result<Result<(), ErrorKind>, MultiErrorKind> {
    // The multi's internal trace, there once a transfer was added.
    table.internal = m.shutdowns.internal().cloned();
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
            m.socket_action(SocketEvent::Timeout, table)
        } else {
            // The newest first, as C's list keeps them; C keeps the last
            // call's result.
            ready.reverse();
            let mut acted = Ok(0);
            for key in ready {
                acted = m.socket_action(SocketEvent::Socket(key), table);
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

#[cfg(test)]
mod tests {
    use super::*;

    /// The table keeps what each socket is watched for, as the socket
    /// callback last said, and forgets one removed.
    #[test]
    fn the_event_table_follows_the_socket_callback() {
        let mut t = EventTable::default();
        let (a, b) = (SocketKey::new(3), SocketKey::new(4));
        t.note(a, SocketWhat::Out).unwrap();
        t.note(b, SocketWhat::In).unwrap();
        assert_eq!(t.sockets, [(a, Events::OUT), (b, Events::IN)]);
        t.note(a, SocketWhat::InOut).unwrap();
        assert_eq!(t.sockets, [(a, Events::IN | Events::OUT), (b, Events::IN)]);
        t.note(a, SocketWhat::Remove).unwrap();
        assert_eq!(t.sockets, [(b, Events::IN)]);
        t.note(b, SocketWhat::Remove).unwrap();
        assert_eq!(t.sockets, []);
    }

    #[test]
    #[should_panic(expected = "removed but never added")]
    fn the_event_table_refuses_a_socket_removed_unknown() {
        let mut t = EventTable::default();
        t.note(SocketKey::new(3), SocketWhat::Remove).unwrap();
    }
}
