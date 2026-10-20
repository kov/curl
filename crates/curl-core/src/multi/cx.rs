//! What a callback may do to the multi that called it: `lib/api.c`'s table
//! of calls allowed inside each callback, as types. A method exists on a
//! context only if C allows that call from that callback.

use curl_alloc::OutOfMemory;

use crate::easy::Easy;
use crate::id::Arena;
use crate::options::Options;

use super::notify::{NotifyKind, NotifyQueue};
use super::{
    AddError, Counts, Host, Message, Multi, MultiEvents, Removed, Slot, Transfer, TransferId,
    read_message,
};

/// The multi as the timer callback sees it: only the calls api.c lets
/// recurse into a running multi call.
pub struct EventCx<'a, H: Host> {
    pub(super) slots: &'a mut Arena<Slot<H>, Transfer>,
    pub(super) notify: &'a mut NotifyQueue,
    pub(super) counts: Counts,
}

impl<H: Host> EventCx<'_, H> {
    pub fn info_read(&mut self) -> Option<Message<'_, H>> {
        read_message(self.slots)
    }

    pub fn counts(&self) -> Counts {
        self.counts
    }

    pub fn set_notify(&mut self, kind: NotifyKind, on: bool) {
        self.notify.set(kind, on);
    }

    pub fn options(&self, id: TransferId) -> Option<&Options> {
        self.slots.get(id).map(|s| s.easy.options())
    }

    pub fn options_mut(&mut self, id: TransferId) -> Option<&mut Options> {
        self.slots.get_mut(id).map(|s| s.easy.options_mut())
    }

    /// A copy of a transfer's `Easy` (`curl_easy_duphandle`).
    pub fn duplicate(&self, id: TransferId) -> Option<Result<Easy, OutOfMemory>> {
        self.slots.get(id).map(|s| s.easy.try_clone())
    }
}

/// The multi as a notification sees it: everything but driving it
/// (`allow_ntfy_cb`). `add` and `remove` call the timer, so they take the
/// events the multi was driven with; a handler passes itself.
pub struct NotifyCx<'a, H: Host> {
    pub(super) multi: &'a mut Multi<H>,
}

impl<H: Host> NotifyCx<'_, H> {
    pub fn add(
        &mut self,
        easy: Easy,
        owner: H::Transfer,
        ev: &mut dyn MultiEvents<H>,
    ) -> Result<TransferId, AddError> {
        self.multi.add(easy, owner, ev)
    }

    pub fn remove(&mut self, id: TransferId, ev: &mut dyn MultiEvents<H>) -> Option<Removed<H>> {
        self.multi.remove(id, ev)
    }

    pub fn info_read(&mut self) -> Option<Message<'_, H>> {
        self.multi.info_read()
    }

    pub fn timeout(&self) -> Option<std::time::Duration> {
        self.multi.timeout()
    }

    pub fn counts(&self) -> Counts {
        self.multi.counts()
    }

    pub fn set_notify(&mut self, kind: NotifyKind, on: bool) {
        self.multi.set_notify(kind, on);
    }

    pub fn options(&self, id: TransferId) -> Option<&Options> {
        self.multi.easy(id).map(Easy::options)
    }

    pub fn options_mut(&mut self, id: TransferId) -> Option<&mut Options> {
        self.multi.easy_mut(id).map(Easy::options_mut)
    }

    pub fn duplicate(&self, id: TransferId) -> Option<Result<Easy, OutOfMemory>> {
        self.multi.easy(id).map(Easy::try_clone)
    }
}
