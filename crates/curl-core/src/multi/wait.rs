//! Waiting for the multi's sockets, the application's descriptors and
//! wakes from other threads (`multi_wait`), and driving one transfer to its
//! end over those waits (`easy_transfer`).

use std::time::Duration;

use curl_alloc::{TryArc, TryVec};

use super::state::{Message as MessageState, TransferState};
use super::{Host, Multi, MultiEvents, TransferId};
use crate::conn::io::{Events, PollFd, Waker};
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
        // No transfer owns a socket yet: the multi's own descriptors are
        // the waker's alone, watched only when the wait will be one.
        let watch_waker = mode == WaitMode::Poll || !extra.is_empty();
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
        if fds.is_empty() && mode == WaitMode::Wait {
            return Ok(0);
        }
        let timeout = self.timeout().map_or(max, |t| t.min(max));
        let mut ready = self
            .net
            .poll(&mut fds, timeout)
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
