//! What a callback may do to the multi that called it: `lib/api.c`'s table
//! of calls allowed inside each callback, as types. A method exists on a
//! context only if C allows that call from that callback.

use curl_alloc::{OutOfMemory, TryVec as _};

use std::fmt;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use crate::components::Component;
use crate::conn::io::{Family, Net, PollFd, ResolveFailure, Sock, Socket, SocketKey, SocketPoll};
use crate::conn::layer::LayerCx;
use crate::conn::shutdown::{Exits, ShutdownSet, WithSet};
use crate::conn::{Caches, ConnCx, DnsCache, Home, Names, Opened, Pool};
use crate::deliver::PauseRequest;
use crate::easy::Easy;
use crate::error::ErrorKind;
use crate::handler::{Configured, Handler, SocketToSet};
use crate::options::Options;
use crate::report::TransferReport;
use crate::share::{Kind, Share, ShareLock, watched};
use crate::time::{Clock, Instant};
use crate::tls::{TlsNative, TlsShared};

use super::notify::{NotifyKind, NotifyQueue};
use super::sched::{RowSet, Tally};
use super::sockets::{Change, SocketFor, SocketOwner, SocketTable, SocketWhat, UnknownSocket};
use super::state::StepCx;
use super::{
    Abort, AddError, Census, ConnLimits, Counts, Host, Life, Message, Multi, MultiEvents, Removed,
    Slots, TransferId, census_of, read_message,
};

/// The multi minus the transfer being stepped, whose `Run` is out of its
/// slot: what a step and the callbacks it makes reach everything else
/// through.
pub(crate) struct EngineRest<'a, H: Host> {
    /// The transfers, and what the socket callback reaches.
    pub(super) tell: Telling<'a, H>,
    pub(super) caches: &'a mut Caches,
    /// What the TLS library keeps across the multi's connections.
    pub(super) tls: &'a mut Option<TlsShared>,
    /// The connections shutting down.
    pub(super) shutdowns: &'a mut ShutdownSet,
    /// The transfer last let look for a connection again.
    pub(super) pending_after: &'a mut Option<TransferId>,
    pub(super) net: &'a mut dyn Net,
    /// IPv6 works, as the multi's probe found.
    pub(crate) ipv6_works: bool,
    pub(super) dirty: &'a mut RowSet,
    /// What the multi was driven with: the socket callback hears of a
    /// socket closing.
    pub(super) events: &'a mut dyn MultiEvents<H>,
    /// The step's time, read by the drive before each step.
    pub(super) now: Instant,
    /// For the drive's reads, and the calendar time, which only a date
    /// needs.
    pub(super) clock: &'a dyn Clock,
    /// The tests' layer each connection set up is given.
    #[cfg(any(test, feature = "test-util"))]
    pub(super) linger: Option<crate::conn::layer::Linger>,
}

impl<H: Host> EngineRest<'_, H> {
    /// The same, borrowed again.
    pub(super) fn reborrow(&mut self) -> EngineRest<'_, H> {
        EngineRest {
            tell: self.tell.reborrow(),
            caches: &mut *self.caches,
            tls: &mut *self.tls,
            shutdowns: &mut *self.shutdowns,
            pending_after: &mut *self.pending_after,
            net: &mut *self.net,
            ipv6_works: self.ipv6_works,
            dirty: &mut *self.dirty,
            events: &mut *self.events,
            now: self.now,
            clock: self.clock,
            #[cfg(any(test, feature = "test-util"))]
            linger: self.linger,
        }
    }

    /// Transfer `who`'s share, if it keeps `kind`, and what the
    /// application watches the share's uses with.
    pub(crate) fn kept(&self, who: TransferId, kind: Kind) -> Option<Kept> {
        let easy = &self
            .tell
            .slots
            .get(who)
            .expect("a transfer of the multi")
            .easy;
        let share = easy.share().filter(|s| s.keeps(kind))?.clone();
        Some(Kept {
            share,
            watch: easy.share_watch.clone(),
        })
    }

    /// Run `section` for transfer `who` on the pool `home` names, with
    /// where the connections it lets go go (the network to close them
    /// through, and the multi's set for those shutting down) and `home`
    /// itself, which leases made there carry: a share's, under its lock
    /// with the application told around it, or the multi's own. The
    /// sockets the section closes are closed once the share's lock is let
    /// go, as closing one tells the socket callback; the section closes no
    /// more than `CloseLater::FEW` (a lease given back), as room for more
    /// is not made. A connection that joined the set is announced after.
    pub(crate) fn pool_section<R>(
        &mut self,
        who: TransferId,
        home: &Home,
        section: impl FnOnce(&mut Pool, &mut dyn Exits, &Home) -> R,
    ) -> R {
        self.section_on(who, home, Room::Few, |pool, exits, here| {
            Ok(section(pool, exits, here))
        })
        .expect("no room is made for a lease given back")
    }

    /// As `pool_section`, for a section that may close any of the pool's
    /// idle connections and of the set's (a search, an addition): room to
    /// hold the socket of each in a share's pool, and in the set, is made
    /// under its lock before the section runs, which does not run without
    /// it.
    pub(crate) fn pool_search<R>(
        &mut self,
        who: TransferId,
        home: &Home,
        section: impl FnOnce(&mut Pool, &mut dyn Exits, &Home) -> Result<R, OutOfMemory>,
    ) -> Result<R, OutOfMemory> {
        self.section_on(who, home, Room::EachConnection, section)
    }

    fn section_on<R>(
        &mut self,
        who: TransferId,
        home: &Home,
        room: Room,
        section: impl FnOnce(&mut Pool, &mut dyn Exits, &Home) -> Result<R, OutOfMemory>,
    ) -> Result<R, OutOfMemory> {
        let watch = self
            .tell
            .slots
            .get(who)
            .expect("a transfer of the multi")
            .easy
            .share_watch
            .clone();
        let max_total = self.tell.limits.max_total;
        let mut net = Announcing {
            net: &mut *self.net,
            tell: self.tell.reborrow(),
            events: &mut *self.events,
            who: SocketFor::Transfer(who),
        };
        let set = &mut *self.shutdowns;
        let r = match home {
            Home::Multi => {
                let mut exits = WithSet {
                    net: &mut net,
                    set,
                    max_total,
                    multi_pool: None,
                };
                section(&mut self.caches.pool, &mut exits, home)
            }
            Home::Share(share) => {
                // The set is capped by the multi's own pool, whichever
                // pool a connection left (conncache.c:236).
                let multi_pool = Some(self.caches.pool.len());
                watched(watch.as_deref(), share, Kind::Connections, || {
                    let mut later = CloseLater::new(&mut net);
                    let r = {
                        let mut pool = share.pool();
                        if room == Room::EachConnection {
                            let each = usize::try_from(pool.len()).expect("a pool's size fits");
                            later.make_room(each + set.len())?;
                        }
                        let mut exits = WithSet {
                            net: &mut later,
                            set,
                            max_total,
                            multi_pool,
                        };
                        section(&mut pool, &mut exits, home)
                    };
                    // The share's lock is let go.
                    later.close();
                    r
                })
            }
        };
        // Told after the section, and out of a share's lock, but before
        // the transfer is assessed again (`cshutdn_update_ev`).
        self.announce_closing();
        r
    }

    /// Tell the socket callback what each connection that joined the set
    /// waits on, as the multi's own (`cshutdn_update_ev`): a socket its
    /// transfer waited on for the same is not told again. One the
    /// callback refuses, or that no room is had for, is closed.
    pub(crate) fn announce_closing(&mut self) {
        announce_closing(
            &mut *self.shutdowns,
            &mut *self.net,
            &mut self.tell,
            &mut *self.events,
        );
    }

    /// The names transfer `who`'s setups look up and keep, with the
    /// network it is to use: its share's names, if that keeps them, else
    /// the multi's own; `kept` is what `kept` gave for `Kind::Names`.
    pub(crate) fn net_names<'k>(
        &'k mut self,
        who: TransferId,
        kept: Option<&'k Kept>,
    ) -> (Announcing<'k, H>, Names<'k>) {
        let net = Announcing {
            net: &mut *self.net,
            tell: self.tell.reborrow(),
            events: &mut *self.events,
            who: SocketFor::Transfer(who),
        };
        (net, names(&mut self.caches.dns, kept))
    }

    /// The network as transfer `who`'s pool uses it, which tells the
    /// socket callback of a socket before it closes.
    pub(crate) fn announcing(&mut self, who: TransferId) -> Announcing<'_, H> {
        Announcing {
            net: &mut *self.net,
            tell: self.tell.reborrow(),
            events: &mut *self.events,
            who: SocketFor::Transfer(who),
        }
    }
}

/// As `EngineRest::announce_closing`, on the multi's parts.
pub(super) fn announce_closing<H: Host>(
    set: &mut ShutdownSet,
    net: &mut dyn Net,
    tell: &mut Telling<'_, H>,
    events: &mut dyn MultiEvents<H>,
) {
    while let Some((id, wants)) = set.next_unannounced() {
        if !events.wants_sockets() {
            continue;
        }
        let mut changes = Vec::new();
        let owner = SocketOwner::Conn(id);
        let told = tell
            .sockets
            .assess(owner, wants.as_slice(), &mut changes)
            .is_ok()
            && self::tell(&changes, SocketFor::Multi, events, tell).is_ok();
        if !told {
            // C closes it ("update events failed").
            let mut net = Announcing {
                net: &mut *net,
                tell: tell.reborrow(),
                events: &mut *events,
                who: SocketFor::Multi,
            };
            set.close_one(id, &mut net);
        }
    }
}

/// The names a setup looks up and keeps: the share's in `kept`, if it
/// keeps them, else the multi's own.
fn names<'k>(own: &'k mut DnsCache, kept: Option<&'k Kept>) -> Names<'k> {
    match kept {
        Some(k) => Names::Shared {
            share: &k.share,
            watch: k.watch(),
        },
        None => Names::Own(own),
    }
}

/// The context a transfer's step drives its connection's setup with
/// (`ConnCx`): the step's own, for the time and the trace; the network,
/// a socket that closes told to the socket callback first, through an
/// `Announcing` made for that close alone; and the names `kept` says.
pub(crate) struct DriveCx<'c, 'a, H: Host> {
    pub(crate) step: &'c mut StepCx<'a, H>,
    pub(crate) kept: Option<&'c Kept>,
}

impl<H: Host> LayerCx for DriveCx<'_, '_, H> {
    fn now(&self) -> Instant {
        self.step.now()
    }

    fn of(&mut self, component: Component, line: fmt::Arguments<'_>) {
        LayerCx::of(&mut *self.step, component, line);
    }

    fn info(&mut self, line: fmt::Arguments<'_>) {
        LayerCx::info(&mut *self.step, line);
    }

    fn socket_failed(&mut self, e: &std::io::Error) {
        LayerCx::socket_failed(&mut *self.step, e);
    }

    fn fails(
        &mut self,
        kind: crate::error::ErrorKind,
        why: fmt::Arguments<'_>,
    ) -> crate::error::ErrorKind {
        LayerCx::fails(&mut *self.step, kind, why)
    }

    fn bytes(&mut self, kind: crate::handler::DebugKind, bytes: &[u8]) {
        LayerCx::bytes(&mut *self.step, kind, bytes);
    }

    fn debugs(&self) -> bool {
        LayerCx::debugs(&*self.step)
    }

    fn certinfo_report(&mut self) -> Option<&mut crate::report::TransferReport> {
        LayerCx::certinfo_report(&mut *self.step)
    }

    fn tls_verified(&mut self, result: i64) {
        LayerCx::tls_verified(&mut *self.step, result);
    }

    fn configures_tls(&self) -> bool {
        LayerCx::configures_tls(&*self.step)
    }

    fn configure_tls(&mut self, native: TlsNative) -> Result<(), crate::error::ErrorKind> {
        LayerCx::configure_tls(&mut *self.step, native)
    }

    fn pause_recv(&mut self) {
        LayerCx::pause_recv(&mut *self.step);
    }
}

impl<H: Host> ConnCx for DriveCx<'_, '_, H> {
    fn net(&mut self) -> &mut dyn Net {
        self
    }

    fn names(&mut self) -> Names<'_> {
        names(&mut self.step.rest.caches.dns, self.kept)
    }

    fn ipv6_works(&self) -> bool {
        self.step.rest.ipv6_works
    }

    fn open_socket(&mut self, address: &mut SocketAddr) -> Opened {
        let opener = self.step.easy().options().sockets.open.clone();
        match opener {
            Some(opener) => Opened {
                socket: opener.open(&mut TransferCx::new(&mut *self.step), address),
                by_application: true,
            },
            None => Opened {
                socket: self.step.rest.net.open(*address),
                by_application: false,
            },
        }
    }

    fn configure_socket(&mut self, socket: &dyn Socket) -> Configured {
        let configurer = self.step.easy().options().sockets.configure.clone();
        match configurer {
            Some(c) => c.configure(&mut TransferCx::new(&mut *self.step), SocketToSet(socket)),
            None => Configured::Ok,
        }
    }

    fn fail(&mut self, reason: fmt::Arguments<'_>) {
        crate::trace::fail(self.step, crate::error::ErrorKind::CouldntConnect, reason);
    }
}

impl<H: Host> Net for DriveCx<'_, '_, H> {
    fn poll(
        &mut self,
        sockets: &mut [SocketPoll<'_>],
        fds: &mut [PollFd<'_>],
        timeout: Duration,
    ) -> io::Result<u32> {
        self.step.rest.net.poll(sockets, fds, timeout)
    }

    fn open(&mut self, addr: SocketAddr) -> io::Result<Box<dyn Socket>> {
        self.step.rest.net.open(addr)
    }

    /// The socket is closed for the transfer: said, then announced as it
    /// goes (`socket_close`, `Curl_multi_will_close`).
    fn close(&mut self, socket: Sock) {
        let fd = socket.key().get();
        super::mstate::trace(self.step, format_args!("Curl_multi_will_close fd={fd}"));
        let me = self.step.me;
        self.step.rest.announcing(me).close(socket);
    }

    fn resolve(&mut self, name: &[u8], family: Family) -> Result<Vec<IpAddr>, ResolveFailure> {
        self.step.rest.net.resolve(name, family)
    }

    fn link_local_scope(&mut self) -> Option<std::num::NonZeroU32> {
        self.step.rest.net.link_local_scope()
    }
}

/// A transfer's share, which keeps a kind of data, and what the
/// application watches its uses with.
pub(crate) struct Kept {
    pub(crate) share: Share,
    watch: Option<Handler<dyn ShareLock>>,
}

impl Kept {
    pub(crate) fn watch(&self) -> Option<&dyn ShareLock> {
        self.watch.as_deref()
    }
}

/// How many sockets a pool section may close: as many as a lease given
/// back holds, or one for each connection in the pool.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Room {
    Few,
    EachConnection,
}

/// A network whose sockets closed are held, to be closed later: out of a
/// share's lock. It holds a few without allocating, and more in room made
/// before the section; a socket it has no room for is a bug, never closed
/// under the lock.
struct CloseLater<'n> {
    net: &'n mut dyn Net,
    few: [Option<Sock>; CloseLater::FEW],
    more: Vec<Sock>,
}

impl<'n> CloseLater<'n> {
    /// The most sockets a lease given back closes: each attempt of a
    /// setup under way, and the idle connection the pool closes over its
    /// limit.
    const FEW: usize = crate::conn::MAX_ATTEMPTS + 1;

    fn new(net: &'n mut dyn Net) -> CloseLater<'n> {
        CloseLater {
            net,
            few: [const { None }; CloseLater::FEW],
            more: Vec::new(),
        }
    }

    /// Room for `n` more sockets than `FEW`.
    fn make_room(&mut self, n: usize) -> Result<(), OutOfMemory> {
        self.more.try_reserve_exact(n).map_err(|_| OutOfMemory)
    }

    /// Close the sockets held, in the order they were.
    fn close(self) {
        let CloseLater { net, few, more } = self;
        for socket in few.into_iter().flatten().chain(more) {
            net.close(socket);
        }
    }
}

impl Net for CloseLater<'_> {
    fn poll(
        &mut self,
        sockets: &mut [SocketPoll<'_>],
        fds: &mut [PollFd<'_>],
        timeout: Duration,
    ) -> io::Result<u32> {
        self.net.poll(sockets, fds, timeout)
    }

    fn open(&mut self, addr: SocketAddr) -> io::Result<Box<dyn Socket>> {
        self.net.open(addr)
    }

    fn close(&mut self, socket: Sock) {
        if let Some(free) = self.few.iter_mut().find(|s| s.is_none()) {
            *free = Some(socket);
            return;
        }
        assert!(
            self.more.len() < self.more.capacity(),
            "no room for {:?}, which would close under the share's lock",
            socket.key()
        );
        self.more.try_push(socket).expect("room was made");
    }

    fn resolve(&mut self, name: &[u8], family: Family) -> Result<Vec<IpAddr>, ResolveFailure> {
        self.net.resolve(name, family)
    }

    fn link_local_scope(&mut self) -> Option<std::num::NonZeroU32> {
        self.net.link_local_scope()
    }
}

/// The multi's network as its pool uses it: a socket a transfer waits on
/// is forgotten, and the socket callback told so, before it closes
/// (`Curl_multi_will_close`, before CLOSESOCKETFUNCTION).
pub(crate) struct Announcing<'a, H: Host> {
    net: &'a mut dyn Net,
    tell: Telling<'a, H>,
    events: &'a mut dyn MultiEvents<H>,
    /// Whom the pool acts for.
    who: SocketFor,
}

impl<'a, H: Host> Announcing<'a, H> {
    /// The network as the multi's own work closes through it: a
    /// connection's shutdown.
    pub(super) fn multi(
        net: &'a mut dyn Net,
        tell: Telling<'a, H>,
        events: &'a mut dyn MultiEvents<H>,
    ) -> Announcing<'a, H> {
        Announcing {
            net,
            tell,
            events,
            who: SocketFor::Multi,
        }
    }
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

    fn open(&mut self, addr: SocketAddr) -> io::Result<Box<dyn Socket>> {
        self.net.open(addr)
    }

    fn close(&mut self, socket: Sock) {
        self.forget(socket.key());
        self.net.close(socket);
    }

    fn resolve(&mut self, name: &[u8], family: Family) -> Result<Vec<IpAddr>, ResolveFailure> {
        self.net.resolve(name, family)
    }

    fn link_local_scope(&mut self) -> Option<std::num::NonZeroU32> {
        self.net.link_local_scope()
    }
}

impl<H: Host> Announcing<'_, H> {
    fn forget(&mut self, key: SocketKey) {
        // A connection's in the set is the multi's own, whoever closes it.
        let who = if self.tell.sockets.has_conn(key) {
            SocketFor::Multi
        } else {
            self.who
        };
        if let Some(change) = self.tell.sockets.forget(key) {
            // An abort leaves the multi dead; the socket closes anyway, as
            // C ignores the callback's answer here.
            let _ = tell(&[change], who, &mut *self.events, &mut self.tell);
        }
    }
}

/// What telling the socket callback reaches: the transfers, and the
/// tables its `EventCx` may read or change.
pub(crate) struct Telling<'a, H: Host> {
    pub(super) slots: &'a mut Slots<H>,
    /// `Multi::conn_limits_mut`.
    pub(super) limits: &'a mut ConnLimits,
    pub(super) notify: &'a mut NotifyQueue,
    pub(super) counts: &'a Tally,
    pub(super) sockets: &'a mut SocketTable<H::Socket>,
    pub(super) life: &'a mut Life,
}

impl<H: Host> Telling<'_, H> {
    /// The same, borrowed again.
    pub(super) fn reborrow(&mut self) -> Telling<'_, H> {
        Telling {
            slots: &mut *self.slots,
            limits: &mut *self.limits,
            notify: &mut *self.notify,
            counts: self.counts,
            sockets: &mut *self.sockets,
            life: &mut *self.life,
        }
    }
}

/// Tell the socket callback of `changes` for `who`, in order,
/// recording each as told; an abort leaves the multi dead and the rest
/// untold (`mev_sh_entry_update`, `mev_forget_socket`).
pub(super) fn tell<H: Host>(
    changes: &[Change<H::Socket>],
    who: SocketFor,
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

    /// As `Multi::census`, this transfer counted as running.
    pub fn census(&self) -> Census {
        self.calls.census()
    }

    pub fn options(&self, id: TransferId) -> Option<&Options> {
        self.calls.easy(id).map(Easy::options)
    }

    /// What a transfer reports so far, its own among them
    /// (`curl_easy_getinfo`).
    pub fn info(&self, id: TransferId) -> Option<&TransferReport> {
        self.calls.easy(id).map(Easy::report)
    }

    /// As `Multi::tls_native`, this transfer's among them.
    pub fn tls_native(&self, id: TransferId) -> Option<TlsNative> {
        self.calls.tls_native(id)
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
    fn census(&self) -> Census;
    fn easy(&self, id: TransferId) -> Option<&Easy>;
    fn easy_mut(&mut self, id: TransferId) -> Option<&mut Easy>;
    fn pause(&mut self, id: TransferId, req: PauseRequest) -> Result<(), ErrorKind>;
    fn fail(&mut self, why: &[u8]);
    fn tls_native(&self, id: TransferId) -> Option<TlsNative>;
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

    /// As `Multi::census`.
    pub fn census(&self) -> Census {
        census_of(self.slots, self.counts)
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

    /// As `Multi::tls_native`.
    pub fn tls_native(&self, id: TransferId) -> Option<TlsNative> {
        super::tls_native_in(self.slots, id)
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
    pub fn add(
        &mut self,
        easy: Box<Easy>,
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

    /// As `Multi::census`.
    pub fn census(&self) -> Census {
        self.multi.census()
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

    /// As `Multi::tls_native`.
    pub fn tls_native(&self, id: TransferId) -> Option<TlsNative> {
        self.multi.tls_native(id)
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::conn::io::{Closer, FakeNet, Peer};
    use crate::time::ManualClock;

    /// The fake network, its closes recorded in order.
    struct Recording(FakeNet, Vec<i32>);

    impl Net for Recording {
        fn poll(
            &mut self,
            sockets: &mut [SocketPoll<'_>],
            fds: &mut [PollFd<'_>],
            timeout: Duration,
        ) -> io::Result<u32> {
            self.0.poll(sockets, fds, timeout)
        }

        fn open(&mut self, addr: SocketAddr) -> io::Result<Box<dyn Socket>> {
            self.0.open(addr)
        }

        fn close(&mut self, socket: Sock) {
            self.1.push(socket.key().get());
            self.0.close(socket);
        }

        fn resolve(&mut self, name: &[u8], family: Family) -> Result<Vec<IpAddr>, ResolveFailure> {
            self.0.resolve(name, family)
        }

        fn link_local_scope(&mut self) -> Option<std::num::NonZeroU32> {
            None
        }
    }

    /// A network and `n` sockets open on it.
    fn opened(n: usize) -> (Recording, Vec<Sock>) {
        let at = SocketAddr::from(([127, 0, 0, 1], 1));
        let mut net = FakeNet::new(ManualClock::new().unwrap()).with_peer(at, Peer::Accepts);
        let socks = (0..n)
            .map(|_| Sock::new(net.open(at).unwrap(), Closer::System))
            .collect();
        (Recording(net, Vec::new()), socks)
    }

    /// Sockets held close only once told, in the order given: a few
    /// without room made, more in the room made.
    #[test]
    fn sockets_held_close_in_order_once_told() {
        let (mut net, socks) = opened(CloseLater::FEW + 2);
        let mut later = CloseLater::new(&mut net);
        later.make_room(2).unwrap();
        for s in socks {
            Net::close(&mut later, s);
        }
        assert!(later.few.iter().all(Option::is_some));
        assert_eq!(later.more.len(), 2, "none closed yet");
        later.close();
        let want: Vec<i32> = (1000..1000 + CloseLater::FEW as i32 + 2).collect();
        assert_eq!(net.1, want);
        assert_eq!(net.0.open_sockets(), 0);
    }

    /// The most a lease given back closes, each attempt of a setup and
    /// the idle connection the pool closes over its limit, is held
    /// without room made.
    #[test]
    fn a_lease_given_back_closes_without_room_made() {
        let n = crate::conn::MAX_ATTEMPTS + 1;
        let (mut net, socks) = opened(n);
        let mut later = CloseLater::new(&mut net);
        for s in socks {
            Net::close(&mut later, s);
        }
        later.close();
        assert_eq!(net.1.len(), n);
        assert_eq!(net.0.open_sockets(), 0);
    }

    /// A section closing more sockets than room was made for is a bug,
    /// caught as it is made rather than closed under the share's lock.
    #[test]
    #[should_panic = "would close under the share's lock"]
    fn a_socket_without_room_is_caught() {
        let (mut net, socks) = opened(CloseLater::FEW + 1);
        let mut later = CloseLater::new(&mut net);
        for s in socks {
            Net::close(&mut later, s);
        }
    }
}
