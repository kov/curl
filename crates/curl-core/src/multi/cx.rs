//! What a callback may do to the multi that called it: `lib/api.c`'s table
//! of calls allowed inside each callback, as types. A method exists on a
//! context only if C allows that call from that callback.

use curl_alloc::OutOfMemory;

use crate::conn::Pool;
use crate::conn::io::Net;
use crate::deliver::PauseRequest;
use crate::easy::Easy;
use crate::error::ErrorKind;
use crate::id::Arena;
use crate::options::Options;
use crate::report::TransferReport;
use crate::time::Instant;

use super::notify::{NotifyKind, NotifyQueue};
use super::sched::RowSet;
use super::{
    AddError, Counts, Host, Message, Multi, MultiEvents, Removed, Slot, Transfer, TransferId,
    read_message,
};

/// The multi minus the transfer being stepped, whose `Run` is out of its
/// slot: what a step and the callbacks it makes reach everything else
/// through.
pub(crate) struct EngineRest<'a, H: Host> {
    pub(super) slots: &'a mut Arena<Slot<H>, Transfer>,
    pub(super) pool: &'a mut Pool,
    pub(super) net: &'a mut dyn Net,
    pub(super) dirty: &'a mut RowSet,
    /// The pass's time, read once.
    pub(super) now: Instant,
}

/// The multi as a transfer's own handlers see it: the calls api.c lets a
/// write, header or read callback make. It names no `Host`, as the
/// handlers live in an `Easy`, which has none.
pub struct TransferCx<'a> {
    calls: &'a mut dyn TransferCalls,
}

impl<'a> TransferCx<'a> {
    pub(crate) fn new(calls: &'a mut dyn TransferCalls) -> TransferCx<'a> {
        TransferCx { calls }
    }

    /// The transfer whose handler this is.
    pub fn me(&self) -> TransferId {
        self.calls.me()
    }

    pub fn options(&self, id: TransferId) -> Option<&Options> {
        self.calls.easy(id).map(Easy::options)
    }

    /// What a transfer reports so far, its own among them
    /// (`curl_easy_getinfo`).
    pub fn info(&self, id: TransferId) -> Option<&TransferReport> {
        self.calls.easy(id).map(Easy::report)
    }

    /// A transfer's options, its own among them: a handler it installs
    /// takes the next piece of output.
    pub fn options_mut(&mut self, id: TransferId) -> Option<&mut Options> {
        self.calls.easy_mut(id).map(Easy::options_mut)
    }

    /// A copy of a transfer's `Easy` (`curl_easy_duphandle`).
    pub fn duplicate(&self, id: TransferId) -> Option<Result<Easy, OutOfMemory>> {
        self.calls.easy(id).map(Easy::try_clone)
    }

    /// Pause or unpause a transfer, this one among them
    /// (`curl_easy_pause`). Another's held output is replayed before this
    /// returns; this one's, by the replay or step already under way. The
    /// timer hears of it at the end of the pass.
    pub fn pause(&mut self, id: TransferId, req: PauseRequest) -> Result<(), ErrorKind> {
        self.calls.pause(id, req)
    }

    /// Why this transfer fails, in the handler's words, before it answers
    /// that it failed: the transfer gives this reason instead of its own.
    /// As every reason, it is traced, and kept unless one came before.
    pub fn fail(&mut self, why: &[u8]) {
        self.calls.fail(why);
    }
}

/// What a `TransferCx` reaches, whatever the multi's `Host`.
pub(crate) trait TransferCalls {
    fn me(&self) -> TransferId;
    fn easy(&self, id: TransferId) -> Option<&Easy>;
    fn easy_mut(&mut self, id: TransferId) -> Option<&mut Easy>;
    fn pause(&mut self, id: TransferId, req: PauseRequest) -> Result<(), ErrorKind>;
    fn fail(&mut self, why: &[u8]);
}

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

    pub fn info(&self, id: TransferId) -> Option<&TransferReport> {
        self.slots.get(id).map(|s| s.easy.report())
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

    pub fn info(&self, id: TransferId) -> Option<&TransferReport> {
        self.multi.easy(id).map(Easy::report)
    }

    /// As `Multi::owner`.
    pub fn owner(&self, id: TransferId) -> Option<&H::Transfer> {
        self.multi.owner(id)
    }

    /// As `Multi::pause`.
    pub fn pause(
        &mut self,
        id: TransferId,
        req: PauseRequest,
        ev: &mut dyn MultiEvents<H>,
    ) -> Result<(), ErrorKind> {
        self.multi.pause(id, req, ev)
    }

    pub fn options_mut(&mut self, id: TransferId) -> Option<&mut Options> {
        self.multi.easy_mut(id).map(Easy::options_mut)
    }

    pub fn duplicate(&self, id: TransferId) -> Option<Result<Easy, OutOfMemory>> {
        self.multi.easy(id).map(Easy::try_clone)
    }
}
