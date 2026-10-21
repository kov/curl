//! What a callback may do to the multi that called it: `lib/api.c`'s table
//! of calls allowed inside each callback, as types. A method exists on a
//! context only if C allows that call from that callback.

use curl_alloc::OutOfMemory;

use std::io;
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use crate::conn::io::{
    Connect, Family, Net, PollFd, ResolveFailure, Socket, SocketKey, SocketPoll,
};
use crate::conn::{DnsCache, Pool};
use crate::deliver::PauseRequest;
use crate::easy::Easy;
use crate::error::ErrorKind;
use crate::options::Options;
use crate::report::TransferReport;
use crate::time::{Clock, Instant};

use super::notify::{NotifyKind, NotifyQueue};
use super::sched::{RowSet, Tally};
use super::sockets::{Change, SocketTable, SocketWhat, UnknownSocket};
use super::{
    Abort, AddError, ConnLimits, Counts, Host, Life, Message, Multi, MultiEvents, Removed, Slots,
    TransferId, read_message,
};

/// The multi minus the transfer being stepped, whose `Run` is out of its
/// slot: what a step and the callbacks it makes reach everything else
/// through.
pub(crate) struct EngineRest<'a, H: Host> {
    pub(super) slots: &'a mut Slots<H>,
    pub(super) pool: &'a mut Pool,
    pub(super) dns: &'a mut DnsCache,
    /// `Multi::conn_limits_mut`.
    pub(super) limits: &'a mut ConnLimits,
    /// The transfer last let look for a connection again.
    pub(super) pending_after: &'a mut Option<TransferId>,
    pub(super) net: &'a mut dyn Net,
    pub(super) dirty: &'a mut RowSet,
    pub(super) sockets: &'a mut SocketTable<H::Socket>,
    pub(super) notify: &'a mut NotifyQueue,
    pub(super) counts: &'a Tally,
    pub(super) life: &'a mut Life,
    /// What the multi was driven with: the socket callback hears of a
    /// socket closing.
    pub(super) events: &'a mut dyn MultiEvents<H>,
    /// The pass's time, read once.
    pub(super) now: Instant,
    /// For the calendar time, which only a date needs.
    pub(super) clock: &'a dyn Clock,
}

impl<H: Host> EngineRest<'_, H> {
    /// The same, borrowed again.
    pub(super) fn reborrow(&mut self) -> EngineRest<'_, H> {
        EngineRest {
            slots: &mut *self.slots,
            pool: &mut *self.pool,
            dns: &mut *self.dns,
            limits: &mut *self.limits,
            pending_after: &mut *self.pending_after,
            net: &mut *self.net,
            dirty: &mut *self.dirty,
            sockets: &mut *self.sockets,
            notify: &mut *self.notify,
            counts: self.counts,
            life: &mut *self.life,
            events: &mut *self.events,
            now: self.now,
            clock: self.clock,
        }
    }

    /// The pool, the network it is to use for transfer `who`, and the
    /// answers kept, for a connection's setup.
    pub(crate) fn pool_net_dns(
        &mut self,
        who: TransferId,
    ) -> (&mut Pool, Announcing<'_, H>, &mut DnsCache) {
        let net = Announcing {
            net: &mut *self.net,
            sockets: &mut *self.sockets,
            slots: &mut *self.slots,
            limits: &mut *self.limits,
            notify: &mut *self.notify,
            counts: self.counts,
            life: &mut *self.life,
            events: &mut *self.events,
            who,
        };
        (&mut *self.pool, net, &mut *self.dns)
    }

    /// The pool, and the network it is to use for transfer `who`: one
    /// that tells the socket callback of a socket before it closes.
    pub(crate) fn pool_net(&mut self, who: TransferId) -> (&mut Pool, Announcing<'_, H>) {
        let (pool, net, _) = self.pool_net_dns(who);
        (pool, net)
    }
}

/// The multi's network as its pool uses it: a socket a transfer waits on
/// is forgotten, and the socket callback told so, before it closes
/// (`Curl_multi_will_close`, before CLOSESOCKETFUNCTION).
pub(crate) struct Announcing<'a, H: Host> {
    net: &'a mut dyn Net,
    sockets: &'a mut SocketTable<H::Socket>,
    slots: &'a mut Slots<H>,
    limits: &'a mut ConnLimits,
    notify: &'a mut NotifyQueue,
    counts: &'a Tally,
    life: &'a mut Life,
    events: &'a mut dyn MultiEvents<H>,
    /// The transfer the pool acts for.
    who: TransferId,
}

impl<H: Host> Net for Announcing<'_, H> {
    fn poll(
        &mut self,
        sockets: &mut [SocketPoll<'_>],
        fds: &mut [PollFd<'_>],
        timeout: Duration,
    ) -> io::Result<u32> {
        self.net.poll(sockets, fds, timeout)
    }

    fn connect(&mut self, addr: SocketAddr) -> io::Result<(Box<dyn Socket>, Connect)> {
        self.net.connect(addr)
    }

    fn close(&mut self, socket: Box<dyn Socket>) {
        self.forget(socket.key());
        self.net.close(socket);
    }

    fn resolve(&mut self, name: &[u8], family: Family) -> Result<Vec<IpAddr>, ResolveFailure> {
        self.net.resolve(name, family)
    }
}

impl<H: Host> Announcing<'_, H> {
    fn forget(&mut self, key: SocketKey) {
        if let Some(change) = self.sockets.forget(key) {
            // An abort leaves the multi dead; the socket closes anyway, as
            // C ignores the callback's answer here.
            let _ = tell(
                &[change],
                self.who,
                &mut *self.events,
                &mut Telling {
                    slots: &mut *self.slots,
                    limits: &mut *self.limits,
                    notify: &mut *self.notify,
                    counts: self.counts,
                    sockets: &mut *self.sockets,
                    life: &mut *self.life,
                },
            );
        }
    }
}

/// What telling the socket callback reaches.
pub(super) struct Telling<'a, H: Host> {
    pub(super) slots: &'a mut Slots<H>,
    pub(super) limits: &'a mut ConnLimits,
    pub(super) notify: &'a mut NotifyQueue,
    pub(super) counts: &'a Tally,
    pub(super) sockets: &'a mut SocketTable<H::Socket>,
    pub(super) life: &'a mut Life,
}

/// Tell the socket callback of `changes` for transfer `who`, in order,
/// recording each as told; an abort leaves the multi dead and the rest
/// untold (`mev_sh_entry_update`, `mev_forget_socket`).
pub(super) fn tell<H: Host>(
    changes: &[Change<H::Socket>],
    who: TransferId,
    events: &mut dyn MultiEvents<H>,
    t: &mut Telling<'_, H>,
) -> Result<(), Abort> {
    if !events.wants_sockets() {
        return Ok(());
    }
    for change in changes {
        let assigned = match change.what {
            SocketWhat::Remove => change.removed_with,
            _ => t.sockets.assigned(change.key),
        };
        let mut cx = EventCx {
            slots: &mut *t.slots,
            limits: &mut *t.limits,
            notify: &mut *t.notify,
            counts: t.counts.get(),
            sockets: &mut *t.sockets,
        };
        if let Err(Abort) = events.socket(&mut cx, who, change.key, change.what, assigned) {
            *t.life = Life::Dead;
            return Err(Abort);
        }
        t.sockets.told(change.key, change.what);
    }
    Ok(())
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
    pub(super) slots: &'a mut Slots<H>,
    pub(super) limits: &'a mut ConnLimits,
    pub(super) notify: &'a mut NotifyQueue,
    pub(super) counts: Counts,
    pub(super) sockets: &'a mut SocketTable<H::Socket>,
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

    /// As `Multi::conn_limits_mut`.
    pub fn conn_limits_mut(&mut self) -> &mut ConnLimits {
        self.limits
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

    /// What the application gave with the transfer when it added it.
    pub fn owner(&self, id: TransferId) -> Option<&H::Transfer> {
        self.slots.get(id).map(|s| &s.owner)
    }

    /// As `Multi::assign`.
    pub fn assign(&mut self, s: SocketKey, value: Option<H::Socket>) -> Result<(), UnknownSocket> {
        self.sockets.assign(s, value)
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

    /// As `Multi::conn_limits_mut`.
    pub fn conn_limits_mut(&mut self) -> &mut ConnLimits {
        self.multi.conn_limits_mut()
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

    /// As `Multi::assign`.
    pub fn assign(&mut self, s: SocketKey, value: Option<H::Socket>) -> Result<(), UnknownSocket> {
        self.multi.assign(s, value)
    }
}
