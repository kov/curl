//! What a callback may do to the multi that called it: `lib/api.c`'s table
//! of calls allowed inside each callback, as types. A method exists on a
//! context only if C allows that call from that callback.

use crate::conn::quic::RecvRoom;
use curl_alloc::{OutOfMemory, TryArc, TryVec as _};
use std::num::NonZeroU32;

use std::io;
use std::time::Duration;

use crate::conn::io::{Events, Net, PollFd, Resolver, Sock, Socket, SocketKey, SocketPoll, Waker};
use crate::conn::layer::LayerCx;
use crate::conn::shutdown::{Exits, Linger, ShutdownSet, WithSet};
use crate::conn::threaded::ResolverThreads;
use crate::conn::{Caches, ConnCx, DnsCache, Home, Names, Opened, Pool};
use crate::deliver::PauseRequest;
use crate::easy::Easy;
use crate::error::ErrorKind;
use crate::handler::{Configured, Handler, SocketToSet};
use crate::options::Options;
use crate::report::TransferReport;
use crate::share::{Kind, Share, ShareLock, watched};
use crate::time::Instant;
use crate::tls::{TlsNative, TlsShared};

use super::notify::{NotifyKind, NotifyQueue};
use super::sched::{RowSet, Tally};
use super::sockets::{Change, SocketFor, SocketOwner, SocketTable, SocketWhat, UnknownSocket};
use super::state::StepCx;
use super::timers::TimerQueue;
use super::{
    Abort, AddError, Census, ConnLimits, Counts, Host, Life, Message, Multi, MultiEvents, Removed,
    Slots, Transfer, TransferId, census_of, read_message,
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
    /// The room QUIC's datagrams are received in, lent while a step reads
    /// them.
    pub(super) sockbuf: &'a mut RecvRoom,
    /// The connections shutting down.
    pub(super) shutdowns: &'a mut ShutdownSet,
    /// The transfers waiting for room for a connection.
    pub(super) pending: &'a mut super::pending::PendingQueue,
    pub(super) net: &'a mut dyn Net,
    /// IPv6 works, as the multi's probe found.
    pub(crate) ipv6_works: bool,
    /// Resolves of IPv6 addresses alone fail, as the debug build asks.
    pub(crate) fail_ipv6: bool,
    pub(super) dirty: &'a mut RowSet,
    /// The transfers' timers: a step reserves a row of them for a transfer
    /// it adds.
    pub(super) timers: &'a mut TimerQueue<Transfer>,
    /// What the multi was driven with: the socket callback hears of a
    /// socket closing.
    pub(super) events: &'a mut dyn MultiEvents<H>,
    /// The step's time, read by the drive before each step.
    pub(super) now: Instant,
    /// For the drive's reads, and the calendar time, which only a date
    /// needs.
    pub(super) clock: &'a crate::time::SharedClock,
    /// The count of lookups dropped each resolve over DoH started shares.
    pub(super) reaping: &'a mut super::doh::Reaping,
    /// A pushed transfer the step added could not start: marked in its
    /// slot, it is taken out as the step ends.
    pub(super) discards: &'a mut bool,
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
            sockbuf: &mut *self.sockbuf,
            shutdowns: &mut *self.shutdowns,
            pending: &mut *self.pending,
            net: &mut *self.net,
            ipv6_works: self.ipv6_works,
            fail_ipv6: self.fail_ipv6,
            dirty: &mut *self.dirty,
            timers: &mut *self.timers,
            events: &mut *self.events,
            now: self.now,
            clock: self.clock,
            reaping: &mut *self.reaping,
            discards: &mut *self.discards,
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
        let share = easy.shared(kind)?.clone();
        share.used_under(self.clock);
        share.traced_by(easy.components());
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
        let recv = &mut *self.sockbuf;
        let r = match home {
            Home::Multi => {
                let mut exits = WithSet {
                    net: &mut net,
                    set,
                    max_total,
                    multi_pool: None,
                    room: recv,
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
                            room: recv,
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
            self.now,
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
        (net, names(&mut self.caches.dns, self.now, kept))
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

/// Keep alive the connections of the pool a handle's are in, every
/// `interval` (`Curl_cpool_upkeep`): `share`'s, if it keeps connections,
/// under its lock, whose idle connections a failed keep-alive closes
/// once the lock is let go; else `pool`, the multi's. A connection closed
/// goes through `net` into the multi's set, `multi`, as the multi's own
/// work.
pub(super) fn upkeep(
    pool: &mut Pool,
    share: Option<(&Share, Option<&dyn ShareLock>)>,
    net: &mut dyn Net,
    multi: Linger<'_>,
    interval: Duration,
    now: Instant,
) -> Result<(), OutOfMemory> {
    let Linger {
        set,
        max_total,
        room,
        ..
    } = multi;
    let Some((share, watch)) = share else {
        let mut exits = WithSet {
            net,
            set,
            max_total,
            multi_pool: None,
            room,
        };
        pool.upkeep(interval, &mut exits, now);
        return Ok(());
    };
    // The set is capped by the multi's own pool (conncache.c:236).
    let multi_pool = Some(pool.len());
    watched(watch, share, Kind::Connections, || {
        let mut later = CloseLater::new(net);
        {
            let mut shared = share.pool();
            // Each connection may close.
            let each = usize::try_from(shared.len()).expect("a pool's size fits");
            later.make_room(each)?;
            let mut exits = WithSet {
                net: &mut later,
                set,
                max_total,
                multi_pool,
                room,
            };
            shared.upkeep(interval, &mut exits, now);
        }
        // The share's lock is let go.
        later.close();
        Ok(())
    })
}

/// As `EngineRest::announce_closing`, on the multi's parts.
pub(super) fn announce_closing<H: Host>(
    set: &mut ShutdownSet,
    net: &mut dyn Net,
    tell: &mut Telling<'_, H>,
    events: &mut dyn MultiEvents<H>,
    now: Instant,
) {
    while let Some((id, wants)) = set.next_unannounced() {
        if !events.wants_sockets() {
            continue;
        }
        set.say_pollset_of(id, now);
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
fn names<'k>(own: &'k mut DnsCache, now: Instant, kept: Option<&'k Kept>) -> Names<'k> {
    match kept {
        Some(k) => Names::Shared {
            share: &k.share,
            watch: k.watch(),
        },
        None => Names::Own { cache: own, now },
    }
}

/// The context a transfer's step drives its connection's setup with
/// (`ConnCx`): the step's own, for the time and the trace; the network,
/// a socket that closes told to the socket callback first, through an
/// `Announcing` made for that close alone; and the transfer's names.
pub(crate) struct DriveCx<'c, 'a, H: Host> {
    pub(crate) step: &'c mut StepCx<'a, H>,
    /// The share the transfer keeps its names in, if it does: taken from
    /// the transfer, so that whatever drives a setup reaches the cache
    /// the transfer looks its names up in.
    kept: Option<Kept>,
    /// The transfer's timers, which a QUIC attempt arms its library's in:
    /// none for a redial, which dials TCP.
    pub(crate) deadlines: Option<&'c mut crate::multi::timers::Deadlines>,
    /// The origin's HTTPS record, if known, for a QUIC attempt the drive
    /// makes: set where the transfer drives its attempts.
    record: Option<TryArc<crate::doh::HttpsRecord>>,
}

impl<'c, 'a, H: Host> DriveCx<'c, 'a, H> {
    pub(crate) fn new(
        step: &'c mut StepCx<'a, H>,
        deadlines: Option<&'c mut crate::multi::timers::Deadlines>,
    ) -> DriveCx<'c, 'a, H> {
        let kept = step.rest.kept(step.me, Kind::Names);
        DriveCx {
            step,
            kept,
            deadlines,
            record: None,
        }
    }

    /// The same, a QUIC attempt it makes knowing the origin's HTTPS
    /// record `record`.
    pub(crate) fn knowing(
        mut self,
        record: Option<TryArc<crate::doh::HttpsRecord>>,
    ) -> DriveCx<'c, 'a, H> {
        self.record = record;
        self
    }
}

/// The step's, but for its timer, which a QUIC attempt arms in the
/// transfer's timers; a setup has no streams to hear of, and hears no
/// handshake that sent early data end: such a connection is connected at
/// once, its handshake ending in the step that drives it on.
impl<H: Host> LayerCx for DriveCx<'_, '_, H> {
    fn now(&self) -> Instant {
        self.step.now()
    }

    fn trace(&mut self) -> Option<&mut dyn crate::conn::layer::Trace> {
        LayerCx::trace(&mut *self.step)
    }

    fn failures(&mut self) -> Option<&mut dyn crate::conn::layer::Failures> {
        LayerCx::failures(&mut *self.step)
    }

    fn transfer(&mut self) -> Option<&mut dyn crate::conn::layer::ForTransfer> {
        LayerCx::transfer(&mut *self.step)
    }

    fn tls_sessions(&mut self) -> Option<&mut dyn crate::conn::layer::TlsSessions> {
        LayerCx::tls_sessions(&mut *self.step)
    }

    fn early_data(&mut self) -> Option<&mut dyn crate::conn::layer::EarlyData> {
        None
    }

    fn quic_timer(&mut self) -> Option<&mut dyn crate::conn::layer::QuicTimer> {
        Some(self)
    }

    fn h3_streams(&mut self) -> Option<&mut dyn crate::conn::layer::H3Streams> {
        None
    }

    fn recv_room(&mut self) -> Option<&mut crate::conn::quic::RecvRoom> {
        LayerCx::recv_room(&mut *self.step)
    }
}

impl<H: Host> crate::conn::layer::QuicTimer for DriveCx<'_, '_, H> {
    fn due_in(&mut self, wait: Duration) {
        let deadlines = self
            .deadlines
            .as_deref_mut()
            .expect("a QUIC attempt is driven with the transfer's timers");
        super::state::arm_quic(deadlines, self.step, wait);
    }
}

impl<H: Host> ConnCx for DriveCx<'_, '_, H> {
    fn net(&mut self) -> &mut dyn Net {
        self
    }

    fn quic_making(&mut self) -> Result<Option<crate::conn::QuicMaking>, curl_alloc::OutOfMemory> {
        let libraries = self.step.easy().shared_libraries();
        if libraries.h3.is_none() || libraries.tls.is_none() {
            return Ok(None);
        }
        let shared = match &mut *self.step.rest.tls {
            Some(shared) => shared.clone(),
            none => none.insert(TlsShared::new()?).clone(),
        };
        // The connection's limit, or C's own (`QUIC_HANDSHAKE_TIMEOUT`).
        let handshake_timeout = self
            .step
            .easy()
            .options()
            .limits
            .connect
            .map_or(Duration::from_secs(10), |l| l.duration());
        Ok(Some(crate::conn::QuicMaking {
            libraries,
            shared,
            handshake_timeout,
            clock: self.step.rest.clock.clone(),
            requests: !self.step.easy().options().connect_only.reserves(),
        }))
    }

    fn https_record(&self) -> Option<TryArc<crate::doh::HttpsRecord>> {
        self.record.clone()
    }

    fn names(&mut self) -> Names<'_> {
        let now = self.step.now();
        names(&mut self.step.rest.caches.dns, now, self.kept.as_ref())
    }

    fn ipv6_works(&self) -> bool {
        self.step.rest.ipv6_works
    }

    fn transfer_number(&self) -> u64 {
        self.step
            .easy()
            .report()
            .transfer_number()
            .map_or(0, |n| n.get())
    }

    fn rank(&self) -> super::state::ConnRank {
        self.step.rank()
    }

    fn resolve_kept(&mut self, holder: crate::conn::asyncs::Holder) -> Result<(), OutOfMemory> {
        super::state::async_kept(self.step, holder)
    }

    fn resolve_gone(&mut self, holder: crate::conn::asyncs::Holder) {
        super::state::async_gone(self.step, holder);
    }

    fn resolve_shut(&mut self, holder: crate::conn::asyncs::Holder) {
        super::state::async_shut(self.step, holder);
    }

    fn resolve_answered_by_library(&mut self, holder: crate::conn::asyncs::Holder) {
        self.step.easy_mut().asyncs.answered_by_library(holder);
    }

    fn resolve_number(
        &self,
        holder: crate::conn::asyncs::Holder,
    ) -> Option<crate::conn::asyncs::ResolveNumber> {
        self.step.easy().asyncs.newest(holder)
    }

    fn hold(&mut self, holder: crate::conn::asyncs::Holder) {
        let rank = self.step.rank();
        self.step.holds_mut().hold(holder, rank);
    }

    fn fails_ipv6_resolves(&self) -> bool {
        self.step.rest.fail_ipv6
    }

    fn waiter(&self) -> crate::conn::io::Waiter {
        crate::conn::io::Waiter(Some(self.step.me()))
    }

    fn open_socket(
        &mut self,
        address: &mut crate::conn::io::Remote,
        kind: crate::conn::io::SocketKind,
    ) -> Opened {
        let opener = self.step.easy().options().sockets.open.clone();
        match opener {
            Some(opener) => Opened {
                socket: opener.open(&mut TransferCx::new(&mut *self.step), address, kind),
                by_application: true,
            },
            None => Opened {
                socket: self.step.rest.net.open(address, kind),
                by_application: false,
            },
        }
    }

    fn configure_socket(&mut self, socket: &dyn Socket) -> Configured {
        let configurer = self.step.easy().options().sockets.configure.clone();
        match configurer {
            Some(c) => c.configure(
                &mut TransferCx::new(&mut *self.step),
                SocketToSet(socket, crate::handler::SocketPurpose::Connect),
            ),
            None => Configured::Ok,
        }
    }

    fn fail_with(&mut self, parts: &[&[u8]]) {
        crate::trace::fail_with(self.step, crate::error::ErrorKind::CouldntConnect, parts);
    }

    fn reset_fail(&mut self) {
        crate::trace::reset_fail(self.step);
    }

    fn wants_doh(&self) -> bool {
        self.step.easy().options().doh.url.is_some()
    }

    fn shuffle(&mut self, addrs: &mut [std::net::IpAddr]) -> Result<bool, OutOfMemory> {
        super::state::shuffle(self.step, addrs)
    }

    fn await_resolve_left(&mut self, since: Instant) -> Option<Duration> {
        let now = self.step.rest.clock.now();
        match self.step.time_left_at(now) {
            super::timers::TimeLeft::Remaining(left) => Some(left),
            super::timers::TimeLeft::Expired(_) => None,
            // `CURL_TIMEOUT_RESOLVE_MS`.
            // In milliseconds, as C counts them.
            super::timers::TimeLeft::Unlimited => {
                let left = 300_000 - now.ms_since(since);
                (left > 0).then(|| Duration::from_millis(left.unsigned_abs()))
            }
        }
    }

    fn libraries_closed(&mut self) {
        self.step.libraries_closed();
    }

    fn await_resolve_tick(&mut self) -> Result<(), ()> {
        crate::progress::update(self.step, false).map_err(|_| ())
    }

    fn has_dns_library(&self) -> bool {
        self.step.easy().libraries().dns.is_some()
    }

    fn dns_start(
        &mut self,
        name: &[u8],
        port: u16,
        family: crate::conn::io::Family,
    ) -> Option<Result<Box<dyn crate::conn::io::DnsResolve>, crate::conn::io::DnsRefused>> {
        crate::multi::dns::start(self.step, name, port, Some(family))
    }

    fn doh_start(
        &mut self,
        name: &[u8],
        family: crate::conn::io::Family,
    ) -> Result<crate::multi::doh::Lookup, crate::conn::ConnectError> {
        crate::multi::doh::start(self.step, name, family)
    }

    fn announce_resolve(&mut self) -> Result<(), crate::conn::ConnectError> {
        let Some(handler) = self.step.easy().options().sockets.resolve_start.clone() else {
            return Ok(());
        };
        let dns = crate::components::Component::Dns;
        let say = |step: &mut StepCx<'_, H>, line| crate::trace::of(step, dns, line);
        say(self.step, format_args!("announcing resolve to application"));
        match handler.resolve_starts(&mut TransferCx::new(&mut *self.step)) {
            Ok(()) => Ok(()),
            Err(Abort) => {
                say(self.step, format_args!("application aborted resolve"));
                Err(crate::conn::ConnectError::Aborted)
            }
        }
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

    fn open(
        &mut self,
        addr: &crate::conn::io::Remote,
        kind: crate::conn::io::SocketKind,
    ) -> io::Result<Box<dyn Socket>> {
        self.step.rest.net.open(addr, kind)
    }

    /// The socket is closed for the transfer: said, then announced as it
    /// goes (`socket_close`, `Curl_multi_will_close`).
    fn close(&mut self, socket: Sock) {
        let fd = socket.key().get();
        super::mstate::trace(self.step, format_args!("Curl_multi_will_close fd={fd}"));
        let me = self.step.me;
        self.step.rest.announcing(me).close(socket);
    }

    fn with_resolver(&mut self, f: &mut dyn FnMut(&mut dyn Resolver)) {
        self.step.rest.net.with_resolver(f);
    }

    fn link_local_scope(&mut self) -> Option<std::num::NonZeroU32> {
        self.step.rest.net.link_local_scope()
    }

    fn interface_address(
        &mut self,
        name: &[u8],
        v6: bool,
        remote_scope: crate::conn::io::Ipv6Scope,
        scope_id: u32,
    ) -> crate::conn::io::InterfaceAddress {
        self.step
            .rest
            .net
            .interface_address(name, v6, remote_scope, scope_id)
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

    fn open(
        &mut self,
        addr: &crate::conn::io::Remote,
        kind: crate::conn::io::SocketKind,
    ) -> io::Result<Box<dyn Socket>> {
        self.net.open(addr, kind)
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

    fn with_resolver(&mut self, f: &mut dyn FnMut(&mut dyn Resolver)) {
        self.net.with_resolver(f);
    }

    fn link_local_scope(&mut self) -> Option<std::num::NonZeroU32> {
        self.net.link_local_scope()
    }

    fn interface_address(
        &mut self,
        name: &[u8],
        v6: bool,
        remote_scope: crate::conn::io::Ipv6Scope,
        scope_id: u32,
    ) -> crate::conn::io::InterfaceAddress {
        self.net.interface_address(name, v6, remote_scope, scope_id)
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

    fn open(
        &mut self,
        addr: &crate::conn::io::Remote,
        kind: crate::conn::io::SocketKind,
    ) -> io::Result<Box<dyn Socket>> {
        self.net.open(addr, kind)
    }

    fn close(&mut self, socket: Sock) {
        self.forget(socket.key());
        self.net.close(socket);
    }

    fn with_resolver(&mut self, f: &mut dyn FnMut(&mut dyn Resolver)) {
        self.net.with_resolver(f);
    }

    fn link_local_scope(&mut self) -> Option<std::num::NonZeroU32> {
        self.net.link_local_scope()
    }

    fn interface_address(
        &mut self,
        name: &[u8],
        v6: bool,
        remote_scope: crate::conn::io::Ipv6Scope,
        scope_id: u32,
    ) -> crate::conn::io::InterfaceAddress {
        self.net.interface_address(name, v6, remote_scope, scope_id)
    }
}

impl<H: Host> Announcing<'_, H> {
    /// A socket another library owned closed: nothing waits on it from
    /// here on, and the socket callback is told so.
    pub(crate) fn will_close(&mut self, key: SocketKey) {
        self.forget(key);
    }

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
    pub(super) alive: &'a mut Alive,
    pub(super) slots: &'a mut Slots<H>,
    /// `Multi::conn_limits_mut`.
    pub(super) limits: &'a mut ConnLimits,
    pub(super) notify: &'a mut NotifyQueue,
    pub(super) counts: &'a mut Tally,
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
            counts: &mut *self.counts,
            sockets: &mut *self.sockets,
            life: &mut *self.life,
            alive: &mut *self.alive,
        }
    }

    /// A transfer came alive, running its first step
    /// (`multistate_init`): the first one has the multi listen on the
    /// resolver's wake, told to the socket callback as the multi's own.
    pub(super) fn came_alive(&mut self, events: &mut dyn MultiEvents<H>) -> Result<(), Abort> {
        self.alive.count += 1;
        match self.alive.count {
            1 => self.listen_to_resolver(true, events),
            _ => Ok(()),
        }
    }

    /// A transfer alive is done, or gone: with the last, the multi stops
    /// listening on the resolver's wake (`multi_assess_wakeup`).
    pub(super) fn went(&mut self, events: &mut dyn MultiEvents<H>) {
        self.alive.count -= 1;
        if self.alive.count == 0 {
            // C does not mind the callback's answer here.
            let _unsaid = self.listen_to_resolver(false, events);
        }
    }

    fn listen_to_resolver(
        &mut self,
        on: bool,
        events: &mut dyn MultiEvents<H>,
    ) -> Result<(), Abort> {
        let Some(waker) = &self.alive.waker else {
            return Ok(());
        };
        if !events.wants_sockets() {
            return Ok(());
        }
        let key = SocketKey::of(waker.fd());
        let listen = [(key, Events::IN)];
        let wants: &[(SocketKey, Events)] = if on { &listen } else { &[] };
        let mut changes = Vec::new();
        // Without room to listen, the answers are still taken as the
        // multi next runs.
        if let Err(OutOfMemory) = self
            .sockets
            .assess(SocketOwner::Resolver, wants, &mut changes)
        {
            return Ok(());
        }
        tell(&changes, SocketFor::Multi, events, self)
    }
}

/// How many transfers are alive (C's `xfers_really_alive`), and the
/// resolver's wake, which the multi listens on while any is.
#[derive(Debug, Default)]
pub(crate) struct Alive {
    pub(crate) count: u32,
    pub(crate) waker: Option<TryArc<Waker>>,
    /// The settings of the resolver's threads, if it answers from a pool.
    pub(crate) pool: Option<ResolverThreads>,
}

impl Alive {
    /// As `Multi::set_resolve_threads_max`.
    pub(crate) fn set_resolve_threads_max(&self, max: NonZeroU32) {
        if let Some(pool) = &self.pool {
            pool.set_max_threads(max);
        }
    }

    /// As `Multi::set_quick_exit`.
    pub(crate) fn set_quick_exit(&self, quick: bool) {
        if let Some(pool) = &self.pool {
            pool.set_join(!quick);
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
            alive: &*t.alive,
            slots: &mut *t.slots,
            limits: &mut *t.limits,
            notify: &mut *t.notify,
            counts: &mut *t.counts,
            sockets: &mut *t.sockets,
            pool: None,
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

    /// As `Easy::tell_failure`, of a transfer.
    pub fn tell_failure(&mut self, id: TransferId, why: &[u8]) {
        if let Some(easy) = self.calls.easy_mut(id) {
            easy.tell_failure(why);
        }
    }

    /// As `Easy::forget_url`, of a transfer.
    pub fn forget_url(&mut self, id: TransferId) {
        if let Some(easy) = self.calls.easy_mut(id) {
            easy.forget_url();
        }
    }

    /// As `Easy::show_set_url`, of a transfer.
    pub fn show_set_url(&mut self, id: TransferId) {
        if let Some(easy) = self.calls.easy_mut(id) {
            easy.show_set_url();
        }
    }

    /// What a transfer's RTSP requests number and read.
    pub fn rtsp(&self, id: TransferId) -> Option<crate::easy::RtspState> {
        self.calls.easy(id).map(Easy::rtsp)
    }

    /// The same, to change.
    pub fn rtsp_mut(
        &mut self,
        id: TransferId,
    ) -> Option<Result<&mut crate::easy::RtspState, OutOfMemory>> {
        self.calls.easy_mut(id).map(Easy::rtsp_mut)
    }

    /// A copy of a transfer's `Easy` (`curl_easy_duphandle`).
    pub fn duplicate(&self, id: TransferId) -> Option<Result<Easy, OutOfMemory>> {
        self.duplicate_with(id, &mut |_| Ok(()))
    }

    /// As `duplicate`, through `Easy::try_clone_with`.
    pub fn duplicate_with(
        &self,
        id: TransferId,
        prepare: &mut dyn FnMut(&mut Options) -> Result<(), OutOfMemory>,
    ) -> Option<Result<Easy, OutOfMemory>> {
        self.calls.easy(id).map(|e| e.try_clone_with(prepare))
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

    /// Send `bytes` on this transfer's WebSocket, from its write or read
    /// handler (`curl_ws_send`): a frame `len` long, or more of the frame
    /// under way, as `flags` say, or the bytes as they are if its frames
    /// are raw. The handler waits for the connection to take them all.
    pub fn ws_send(
        &mut self,
        bytes: &[u8],
        len: crate::ws::FrameLen,
        flags: crate::ws::SendFlags,
    ) -> Result<crate::ws::Sent, ErrorKind> {
        let asked = crate::proto::ws::asked_of(len, flags);
        self.calls.ws_send(bytes, &asked)
    }

    /// [`ws_send`](Self::ws_send), the arguments as a host read them from
    /// its own.
    pub fn ws_send_asked(
        &mut self,
        bytes: &[u8],
        asked: &crate::ws::Asked<'_>,
    ) -> Result<crate::ws::Sent, ErrorKind> {
        self.calls.ws_send(bytes, asked)
    }

    /// Start a frame `len` long on this transfer's WebSocket, its payload
    /// to come in the sends after, from its write or read handler: a read
    /// handler's upload gives it (`curl_ws_start_frame`).
    pub fn ws_start_frame(
        &mut self,
        flags: crate::ws::SendFlags,
        len: u64,
    ) -> Result<(), ErrorKind> {
        let asked = crate::proto::ws::start_asked_of(flags, len);
        self.calls.ws_start_frame(&asked)
    }

    /// [`ws_start_frame`](Self::ws_start_frame), the arguments as a host
    /// read them from its own.
    pub fn ws_start_asked(&mut self, asked: &crate::ws::Asked<'_>) -> Result<(), ErrorKind> {
        self.calls.ws_start_frame(asked)
    }

    /// Receive into `buf` what came of the next frame on this transfer's
    /// WebSocket, from its write or read handler (`curl_ws_recv`).
    pub fn ws_recv(&mut self, buf: &mut [u8]) -> Result<crate::ws::Received, ErrorKind> {
        self.calls.ws_recv(buf)
    }

    /// What the bytes the write handler is given are of, on this
    /// transfer's WebSocket, unless frames are raw (`curl_ws_meta`):
    /// none from a handler that is not given its connection.
    pub fn ws_meta(&self) -> Option<crate::ws::Meta> {
        self.calls.ws_meta()
    }
}

/// What a `TransferCx` reaches, whatever the multi's `Host`.
pub(crate) trait TransferCalls {
    fn me(&self) -> TransferId;
    /// Transfer `me`'s own `Easy`, for the library's trace of it: one of
    /// the multi's own among them, which `easy` refuses.
    fn own(&self) -> Option<&Easy>;
    fn census(&self) -> Census;
    fn easy(&self, id: TransferId) -> Option<&Easy>;
    fn easy_mut(&mut self, id: TransferId) -> Option<&mut Easy>;
    fn pause(&mut self, id: TransferId, req: PauseRequest) -> Result<(), ErrorKind>;
    fn fail(&mut self, why: &[u8]);
    fn tls_native(&self, id: TransferId) -> Option<TlsNative>;
    /// The calls on the transfer's WebSocket, as `TransferCx`'s say.
    fn ws_send(
        &mut self,
        bytes: &[u8],
        asked: &crate::ws::Asked<'_>,
    ) -> Result<crate::ws::Sent, ErrorKind>;
    fn ws_start_frame(&mut self, asked: &crate::ws::Asked<'_>) -> Result<(), ErrorKind>;
    fn ws_recv(&mut self, buf: &mut [u8]) -> Result<crate::ws::Received, ErrorKind>;
    fn ws_meta(&self) -> Option<crate::ws::Meta>;
}

/// Transfer `me`'s handlers as one of the multi's callbacks calls them,
/// outside its step (`infof` on the handle a socket callback was given):
/// they reach the transfers as the callback does, and pause none, as only
/// a step does that.
pub(crate) struct EventCalls<'c, 'a, H: Host> {
    pub(crate) cx: &'c mut EventCx<'a, H>,
    pub(crate) me: TransferId,
}

impl<H: Host> TransferCalls for EventCalls<'_, '_, H> {
    fn me(&self) -> TransferId {
        self.me
    }

    fn own(&self) -> Option<&Easy> {
        self.cx.slots.get(self.me).map(|s| &*s.easy)
    }

    fn census(&self) -> Census {
        self.cx.census()
    }

    fn easy(&self, id: TransferId) -> Option<&Easy> {
        self.cx.slots.app(id).map(|s| &*s.easy)
    }

    fn easy_mut(&mut self, id: TransferId) -> Option<&mut Easy> {
        self.cx.slots.app_easy_mut(id)
    }

    fn pause(&mut self, _: TransferId, _: PauseRequest) -> Result<(), ErrorKind> {
        Err(ErrorKind::BadFunctionArgument)
    }

    fn fail(&mut self, _: &[u8]) {}

    fn tls_native(&self, id: TransferId) -> Option<TlsNative> {
        self.cx.tls_native(id)
    }

    // Outside a transfer's handlers, its connection is not lent.
    fn ws_send(
        &mut self,
        _: &[u8],
        _: &crate::ws::Asked<'_>,
    ) -> Result<crate::ws::Sent, ErrorKind> {
        Err(ErrorKind::SendError)
    }

    fn ws_start_frame(&mut self, _: &crate::ws::Asked<'_>) -> Result<(), ErrorKind> {
        Err(ErrorKind::SendError)
    }

    fn ws_recv(&mut self, _: &mut [u8]) -> Result<crate::ws::Received, ErrorKind> {
        Err(ErrorKind::BadFunctionArgument)
    }

    fn ws_meta(&self) -> Option<crate::ws::Meta> {
        None
    }
}

/// A handle's handlers as they are called outside any transfer's step, as
/// it is reset or let go of (`Curl_close`): they reach that handle alone,
/// as `me`, its id in its multi or the lone handle's, and pause nothing.
pub(crate) struct LoneCalls<'a> {
    pub(crate) easy: &'a mut Easy,
    pub(crate) me: TransferId,
}

impl TransferCalls for LoneCalls<'_> {
    fn me(&self) -> TransferId {
        self.me
    }

    fn own(&self) -> Option<&Easy> {
        Some(&*self.easy)
    }

    fn census(&self) -> Census {
        Census {
            counts: Counts::default(),
            pending: 0,
            unread: 0,
        }
    }

    fn easy(&self, id: TransferId) -> Option<&Easy> {
        (id == self.me).then_some(&*self.easy)
    }

    fn easy_mut(&mut self, id: TransferId) -> Option<&mut Easy> {
        (id == self.me).then_some(&mut *self.easy)
    }

    fn pause(&mut self, _: TransferId, _: PauseRequest) -> Result<(), ErrorKind> {
        Err(ErrorKind::BadFunctionArgument)
    }

    fn fail(&mut self, _: &[u8]) {}

    fn tls_native(&self, _: TransferId) -> Option<TlsNative> {
        None
    }

    fn ws_send(
        &mut self,
        _: &[u8],
        _: &crate::ws::Asked<'_>,
    ) -> Result<crate::ws::Sent, ErrorKind> {
        Err(ErrorKind::SendError)
    }

    fn ws_start_frame(&mut self, _: &crate::ws::Asked<'_>) -> Result<(), ErrorKind> {
        Err(ErrorKind::SendError)
    }

    fn ws_recv(&mut self, _: &mut [u8]) -> Result<crate::ws::Received, ErrorKind> {
        Err(ErrorKind::BadFunctionArgument)
    }

    fn ws_meta(&self) -> Option<crate::ws::Meta> {
        None
    }
}

/// The multi as the timer callback sees it: only the calls api.c lets
/// recurse into a running multi call.
pub struct EventCx<'a, H: Host> {
    pub(super) slots: &'a mut Slots<H>,
    pub(super) limits: &'a mut ConnLimits,
    pub(super) notify: &'a mut NotifyQueue,
    pub(super) counts: &'a mut Tally,
    pub(super) sockets: &'a mut SocketTable<H::Socket>,
    pub(super) alive: &'a Alive,
    /// The multi's pool, where a connection that multiplexes is; none
    /// within a step, which has the pool apart.
    pub(super) pool: Option<&'a Pool>,
}

impl<H: Host> EventCx<'_, H> {
    /// As `Multi::set_resolve_threads_max`.
    pub fn set_resolve_threads_max(&mut self, max: NonZeroU32) {
        self.alive.set_resolve_threads_max(max);
    }

    /// As `Multi::set_quick_exit`.
    pub fn set_quick_exit(&mut self, quick: bool) {
        self.alive.set_quick_exit(quick);
    }

    pub fn info_read(&mut self) -> Option<Message<'_, H>> {
        read_message(self.slots, self.counts)
    }

    pub fn counts(&self) -> Counts {
        self.counts.get()
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
        self.slots.app(id).map(|s| s.easy.options())
    }

    pub fn info(&self, id: TransferId) -> Option<&TransferReport> {
        self.slots.app(id).map(|s| s.easy.report())
    }

    /// As `Multi::tls_native`.
    pub fn tls_native(&self, id: TransferId) -> Option<TlsNative> {
        self.slots.app(id)?;
        super::tls_native_in(self.slots, self.pool, id)
    }

    pub fn options_mut(&mut self, id: TransferId) -> Option<&mut Options> {
        self.slots.app_easy_mut(id).map(Easy::options_mut)
    }

    /// As `Easy::tell_failure`, of a transfer.
    pub fn tell_failure(&mut self, id: TransferId, why: &[u8]) {
        if let Some(easy) = self.slots.app_easy_mut(id) {
            easy.tell_failure(why);
        }
    }

    /// As `Easy::forget_url`, of a transfer.
    pub fn forget_url(&mut self, id: TransferId) {
        if let Some(easy) = self.slots.app_easy_mut(id) {
            easy.forget_url();
        }
    }

    /// As `Easy::show_set_url`, of a transfer.
    pub fn show_set_url(&mut self, id: TransferId) {
        if let Some(easy) = self.slots.app_easy_mut(id) {
            easy.show_set_url();
        }
    }

    /// As `TransferCx::rtsp`.
    pub fn rtsp(&self, id: TransferId) -> Option<crate::easy::RtspState> {
        self.slots.app(id).map(|s| s.easy.rtsp())
    }

    /// As `TransferCx::rtsp_mut`.
    pub fn rtsp_mut(
        &mut self,
        id: TransferId,
    ) -> Option<Result<&mut crate::easy::RtspState, OutOfMemory>> {
        self.slots.app_easy_mut(id).map(Easy::rtsp_mut)
    }

    /// A copy of a transfer's `Easy` (`curl_easy_duphandle`).
    pub fn duplicate(&self, id: TransferId) -> Option<Result<Easy, OutOfMemory>> {
        self.duplicate_with(id, &mut |_| Ok(()))
    }

    /// As `duplicate`, through `Easy::try_clone_with`.
    pub fn duplicate_with(
        &self,
        id: TransferId,
        prepare: &mut dyn FnMut(&mut Options) -> Result<(), OutOfMemory>,
    ) -> Option<Result<Easy, OutOfMemory>> {
        self.slots.app(id).map(|s| s.easy.try_clone_with(prepare))
    }

    /// What the application gave with the transfer when it added it.
    pub fn owner(&self, id: TransferId) -> Option<&H::Transfer> {
        self.slots.get(id).and_then(|s| s.owner.host())
    }

    /// What the application gave with each transfer, in id order.
    pub fn owners(&self) -> impl Iterator<Item = &H::Transfer> {
        let mut cursor = None;
        std::iter::from_fn(move || {
            loop {
                let id = self.slots.next_after(cursor)?;
                cursor = Some(id);
                match &self.slots.get(id).expect("just found").owner {
                    crate::multi::Owner::App(host) => return Some(host),
                    crate::multi::Owner::Internal { .. } => {}
                }
            }
        })
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
    /// As `Multi::set_resolve_threads_max`.
    pub fn set_resolve_threads_max(&mut self, max: NonZeroU32) {
        self.multi.set_resolve_threads_max(max);
    }

    /// As `Multi::set_quick_exit`.
    pub fn set_quick_exit(&mut self, quick: bool) {
        self.multi.set_quick_exit(quick);
    }

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

    /// As `Multi::network_changed`.
    pub fn network_changed(&mut self, names: bool, connections: bool, ev: &mut dyn MultiEvents<H>) {
        self.multi.network_changed(names, connections, ev);
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

    /// As `Multi::owners`.
    pub fn owners(&self) -> impl Iterator<Item = &H::Transfer> {
        self.multi.owners()
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
        self.multi.slots.app_easy_mut(id).map(Easy::options_mut)
    }

    /// As `Easy::tell_failure`, of a transfer.
    pub fn tell_failure(&mut self, id: TransferId, why: &[u8]) {
        if let Some(mut easy) = self.multi.easy_mut(id) {
            easy.tell_failure(why);
        }
    }

    /// As `Easy::forget_url`, of a transfer.
    pub fn forget_url(&mut self, id: TransferId) {
        if let Some(mut easy) = self.multi.easy_mut(id) {
            easy.forget_url();
        }
    }

    /// As `Easy::show_set_url`, of a transfer.
    pub fn show_set_url(&mut self, id: TransferId) {
        if let Some(mut easy) = self.multi.easy_mut(id) {
            easy.show_set_url();
        }
    }

    /// As `TransferCx::rtsp`.
    pub fn rtsp(&self, id: TransferId) -> Option<crate::easy::RtspState> {
        self.multi.easy(id).map(Easy::rtsp)
    }

    /// As `TransferCx::rtsp_mut`.
    pub fn rtsp_mut(
        &mut self,
        id: TransferId,
    ) -> Option<Result<&mut crate::easy::RtspState, OutOfMemory>> {
        self.multi.slots.app_easy_mut(id).map(Easy::rtsp_mut)
    }

    pub fn duplicate(&self, id: TransferId) -> Option<Result<Easy, OutOfMemory>> {
        self.duplicate_with(id, &mut |_| Ok(()))
    }

    /// As `duplicate`, through `Easy::try_clone_with`.
    pub fn duplicate_with(
        &self,
        id: TransferId,
        prepare: &mut dyn FnMut(&mut Options) -> Result<(), OutOfMemory>,
    ) -> Option<Result<Easy, OutOfMemory>> {
        self.multi.easy(id).map(|e| e.try_clone_with(prepare))
    }

    /// As `Multi::assign`.
    pub fn assign(&mut self, s: SocketKey, value: Option<H::Socket>) -> Result<(), UnknownSocket> {
        self.multi.assign(s, value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::conn::io::{Closer, FakeNet, Peer, Remote};
    use crate::time::ManualClock;

    /// The fake network, its closes recorded in order.
    struct Recording(FakeNet, Vec<crate::conn::io::RawSocket>);

    impl Net for Recording {
        fn poll(
            &mut self,
            sockets: &mut [SocketPoll<'_>],
            fds: &mut [PollFd<'_>],
            timeout: Duration,
        ) -> io::Result<u32> {
            self.0.poll(sockets, fds, timeout)
        }

        fn open(
            &mut self,
            addr: &crate::conn::io::Remote,
            kind: crate::conn::io::SocketKind,
        ) -> io::Result<Box<dyn Socket>> {
            self.0.open(addr, kind)
        }

        fn close(&mut self, socket: Sock) {
            self.1.push(socket.key().get());
            self.0.close(socket);
        }

        fn with_resolver(&mut self, f: &mut dyn FnMut(&mut dyn Resolver)) {
            self.0.with_resolver(f);
        }

        fn link_local_scope(&mut self) -> Option<std::num::NonZeroU32> {
            None
        }

        fn interface_address(
            &mut self,
            _: &[u8],
            _: bool,
            _: crate::conn::io::Ipv6Scope,
            _: u32,
        ) -> crate::conn::io::InterfaceAddress {
            crate::conn::io::InterfaceAddress::NotFound(0)
        }
    }

    /// A network and `n` sockets open on it.
    fn opened(n: usize) -> (Recording, Vec<Sock>) {
        let at = std::net::SocketAddr::from(([127, 0, 0, 1], 1));
        let mut net = FakeNet::new(ManualClock::new().unwrap()).with_peer(at, Peer::Accepts);
        let socks = (0..n)
            .map(|_| {
                Sock::new(
                    net.open(&Remote::Inet(at), crate::conn::io::SocketKind::Stream)
                        .unwrap(),
                    Closer::System,
                )
            })
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
        let want: Vec<crate::conn::io::RawSocket> =
            (1000..1000 + CloseLater::FEW as crate::conn::io::RawSocket + 2).collect();
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
