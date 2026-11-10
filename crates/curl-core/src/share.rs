//! The share: connections, resolved names, cookies, TLS sessions, the
//! public suffix list and the HSTS cache kept for every transfer given it, whichever handle
//! and thread runs them (`CURLSH`, with `CURL_LOCK_DATA_CONNECT`,
//! `CURL_LOCK_DATA_DNS`, `CURL_LOCK_DATA_COOKIE`,
//! `CURL_LOCK_DATA_SSL_SESSION`, `CURL_LOCK_DATA_PSL` and
//! `CURL_LOCK_DATA_HSTS`).
//!
//! Each kind of data it keeps has a lock of its own, held for one use of
//! it at a time (a search for a connection, a lookup, a cookie stored) and
//! never across a callback, so no transfer waits on another's. A
//! connection a transfer uses is its lease's, not the share's, until it
//! is given back. The application may watch every use, as C calls its
//! lock functions: its `ShareLock` is told before the lock is taken and
//! after it is let go.

use curl_alloc::{Lock, LockGuard};
use std::fmt;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicU8, Ordering};

use curl_alloc::{OutOfMemory, TryArc, try_box};

use crate::conn::io::{Net, SystemNet};
use crate::conn::shutdown::NoSet;
use crate::conn::{DnsCache, Pool};
use crate::cookie::Jar;
use crate::hsts::Hsts;
use crate::multi::SessionsOut;
use crate::psl::PslCache;
use crate::time::{Instant, SharedClock};
use crate::tls::SessionCache;
use crate::trace::Internal;

/// A handle's share cannot change now: the handle holds a connection
/// (`setopt_share`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ShareInUse;

/// A kind of data a share may keep (`curl_lock_data`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    /// Connections left idle (`CURL_LOCK_DATA_CONNECT`).
    Connections,
    /// Names resolved (`CURL_LOCK_DATA_DNS`).
    Names,
    /// Cookies (`CURL_LOCK_DATA_COOKIE`).
    Cookies,
    /// TLS sessions to resume (`CURL_LOCK_DATA_SSL_SESSION`).
    SslSessions,
    /// The public suffix list (`CURL_LOCK_DATA_PSL`).
    Psl,
    /// The HSTS cache (`CURL_LOCK_DATA_HSTS`).
    Hsts,
}

impl Kind {
    /// Its bit in `Inner::keeps`, for a kind whose storage the share
    /// always has; none for one kept as its container is there.
    fn bit(self) -> u8 {
        match self {
            Kind::Connections => 1,
            Kind::Names => 2,
            Kind::Psl => 4,
            Kind::Cookies | Kind::SslSessions | Kind::Hsts => 0,
        }
    }
}

/// What a use of the share's data wants of it (`curl_lock_access`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Access {
    /// To read it, beside others reading it (`CURL_LOCK_ACCESS_SHARED`).
    Shared,
    /// To itself (`CURL_LOCK_ACCESS_SINGLE`).
    Single,
}

/// Told around each use of what a transfer's share keeps, as C calls the
/// share's lock functions with the transfer's handle
/// (`CURLSHOPT_LOCKFUNC`, `CURLSHOPT_UNLOCKFUNC`). The share's own locks
/// guard the data; this lets the application see each use.
pub trait ShareLock: Send + Sync {
    fn lock(&self, kind: Kind, access: Access);
    fn unlock(&self, kind: Kind);
}

/// A share, cloned to give it to another handle.
#[derive(Clone)]
pub struct Share(TryArc<Inner>);

struct Inner {
    /// The kinds it keeps of those whose storage is always there, a bit
    /// each. Cookies, TLS sessions and the HSTS cache are kept exactly
    /// while their container below is: a use takes its lock and finds the
    /// one or the other, so no second fact can disagree with it.
    keeps: AtomicU8,
    pool: Lock<Pool>,
    dns: Lock<DnsCache>,
    /// The jar, made when cookies are first kept.
    cookies: Lock<Option<Jar>>,
    /// The TLS sessions, a cache made when they are first kept.
    sessions: Lock<Option<SessionCache>>,
    /// Whether its sessions are going out to the application's function:
    /// made by the first export, as few shares have one.
    sessions_out: OnceLock<SessionsOut>,
    /// The HSTS cache, made when it is first kept.
    hsts: Lock<Option<Hsts>>,
    /// The public suffix list, used by its transfers in place of each
    /// one's multi's once it is kept. It has a lock of its own.
    psl: PslCache,
    /// What the connections left idle at the end are closed through, as
    /// C's share closes them through its own internal handle.
    net: Lock<Box<dyn Net + Send>>,
    /// The clock of the multis that use it, which must be one: their
    /// names and connections carry its instants. A normal build has only
    /// the system's; a test's share takes the first multi's.
    #[cfg(any(test, feature = "test-util"))]
    clock: OnceLock<SharedClock>,
    /// The debug build's `CURL_DEBUG` was set as the share was made: its
    /// internal trace is on, with the components of the first transfer
    /// that uses it, the process's (C's `share->admin`, made verbose).
    #[cfg(feature = "debug-hooks")]
    traces_internally: bool,
    /// What it does for no transfer is traced here once on: the
    /// connections its pool closes as it goes or keeps alive.
    internal: OnceLock<Internal>,
}

/// A handle holds the share, so what it keeps cannot change.
#[derive(Debug)]
pub struct InUse;

impl Share {
    /// A share keeping nothing yet, whose connections are the system's.
    pub fn new() -> Result<Share, OutOfMemory> {
        Share::over(try_box(SystemNet::default())?)
    }

    /// A test's share keeping nothing yet, whose connections are `net`'s.
    #[cfg(any(test, feature = "test-util"))]
    pub fn with_net(net: Box<dyn Net + Send>) -> Result<Share, OutOfMemory> {
        Share::over(net)
    }

    fn over(net: Box<dyn Net + Send>) -> Result<Share, OutOfMemory> {
        Ok(Share(TryArc::try_new(Inner {
            keeps: AtomicU8::new(0),
            pool: Lock::new(Pool::new()?),
            dns: Lock::new(DnsCache::default()),
            cookies: Lock::new(None),
            sessions: Lock::new(None),
            sessions_out: OnceLock::new(),
            hsts: Lock::new(None),
            psl: PslCache::default(),
            net: Lock::new(net),
            #[cfg(any(test, feature = "test-util"))]
            clock: OnceLock::new(),
            #[cfg(feature = "debug-hooks")]
            traces_internally: curl_os::env::is_set(b"CURL_DEBUG"),
            internal: OnceLock::new(),
        })?))
    }

    /// A transfer tracing `components` uses it: under the debug build's
    /// `CURL_DEBUG` its internal trace is on from now on, with the first
    /// such transfer's components, as C's share makes its own handle
    /// verbose (`curl_share_init`).
    #[cfg_attr(not(feature = "debug-hooks"), allow(unused_variables))]
    pub(crate) fn traced_by(&self, components: Option<&crate::components::Components>) {
        #[cfg(feature = "debug-hooks")]
        if self.0.traces_internally
            && let Some(components) = components
        {
            self.0
                .internal
                .get_or_init(|| Internal::new(components.clone()));
        }
    }

    /// Trace what it does for no transfer to `sink`, as `components` say.
    #[cfg(any(test, feature = "test-util"))]
    pub fn trace_internally_to(
        &self,
        components: crate::components::Components,
        sink: crate::handler::Handler<dyn crate::handler::TextSink>,
    ) {
        self.0
            .internal
            .get_or_init(|| Internal::to(components, sink));
    }

    /// Keep `kind` for the transfers given the share from now on
    /// (`CURLSHOPT_SHARE`): cookies in one jar for them all, each
    /// transfer whose own options turn its jar on using the share's in
    /// its place; TLS sessions in a cache of 25 peers, in place of each
    /// transfer's multi's.
    pub fn keep(&self, kind: Kind) -> Result<(), InUse> {
        self.idle()?;
        match kind {
            Kind::Cookies => {
                lock(&self.0.cookies).get_or_insert_with(Jar::default);
            }
            Kind::SslSessions => {
                let peers = SessionCache::PEERS;
                lock(&self.0.sessions).get_or_insert_with(|| SessionCache::new(peers));
            }
            Kind::Hsts => {
                lock(&self.0.hsts).get_or_insert_with(Hsts::default);
            }
            Kind::Connections | Kind::Names | Kind::Psl => {
                self.0.keeps.fetch_or(kind.bit(), Ordering::Relaxed);
            }
        }
        Ok(())
    }

    /// Keep `kind` no more (`CURLSHOPT_UNSHARE`), forgetting the cookies,
    /// TLS sessions or HSTS cache kept; connections and names stay until the share
    /// goes, as C's do.
    pub fn stop_keeping(&self, kind: Kind) -> Result<(), InUse> {
        self.idle()?;
        self.let_go(kind);
        Ok(())
    }

    fn let_go(&self, kind: Kind) {
        match kind {
            Kind::Cookies => *lock(&self.0.cookies) = None,
            Kind::SslSessions => *lock(&self.0.sessions) = None,
            Kind::Hsts => *lock(&self.0.hsts) = None,
            Kind::Connections | Kind::Names | Kind::Psl => {
                self.0.keeps.fetch_and(!kind.bit(), Ordering::Relaxed);
            }
        }
    }

    /// Whether the share keeps `kind`. For cookies, TLS sessions and the
    /// HSTS cache this is only a forecast: a handle linking on another
    /// thread as the share stops keeping them may find them gone by the
    /// time it takes their lock, and a use answers by what it finds there.
    pub fn keeps(&self, kind: Kind) -> bool {
        match kind {
            Kind::Cookies => lock(&self.0.cookies).is_some(),
            Kind::SslSessions => lock(&self.0.sessions).is_some(),
            Kind::Hsts => lock(&self.0.hsts).is_some(),
            Kind::Connections | Kind::Names | Kind::Psl => {
                self.0.keeps.load(Ordering::Relaxed) & kind.bit() != 0
            }
        }
    }

    /// How many hold the share: its clones, this one among them.
    pub fn holders(&self) -> usize {
        TryArc::count(&self.0)
    }

    /// Whether `other` is this share, not another one.
    pub(crate) fn is(&self, other: &Share) -> bool {
        TryArc::ptr_eq(&self.0, &other.0)
    }

    fn idle(&self) -> Result<(), InUse> {
        if self.holders() > 1 {
            return Err(InUse);
        }
        Ok(())
    }

    /// The connections kept, locked.
    pub(crate) fn pool(&self) -> LockGuard<'_, Pool> {
        lock(&self.0.pool)
    }

    /// Whether its pool is locked now, for the tests of what runs out of
    /// the lock.
    #[cfg(test)]
    pub(crate) fn pool_is_locked(&self) -> bool {
        self.0.pool.try_lock().is_err()
    }

    /// The time its names and public suffixes are stamped and aged by:
    /// the system's, or in a test the clock of the multis that use it.
    pub(crate) fn now(&self) -> Instant {
        #[cfg(any(test, feature = "test-util"))]
        let clock = self
            .0
            .clock
            .get()
            .expect("a share's names are used by a multi first");
        #[cfg(not(any(test, feature = "test-util")))]
        let clock = SharedClock::system();
        clock.now()
    }

    /// A multi reading `clock` uses what the share keeps. Every user of
    /// a share reads one clock, as the system's are all one: in a test,
    /// the share takes the first one's, and the debug build panics at a
    /// use under another.
    #[cfg_attr(not(any(test, feature = "test-util")), allow(unused_variables))]
    pub(crate) fn used_under(&self, clock: &SharedClock) {
        #[cfg(any(test, feature = "test-util"))]
        {
            let kept = self.0.clock.get_or_init(|| clock.clone());
            debug_assert_eq!(
                kept.identity(),
                clock.identity(),
                "a share's users read one clock"
            );
        }
    }

    /// The names kept, locked.
    pub(crate) fn dns(&self) -> LockGuard<'_, DnsCache> {
        lock(&self.0.dns)
    }

    /// The jar, locked; none if the share keeps no cookies.
    pub(crate) fn cookies(&self) -> LockGuard<'_, Option<Jar>> {
        lock(&self.0.cookies)
    }

    /// The HSTS cache, locked; none if the share keeps none.
    pub(crate) fn hsts(&self) -> LockGuard<'_, Option<Hsts>> {
        lock(&self.0.hsts)
    }

    /// Whether its HSTS cache is locked now, for the tests of what runs
    /// out of the lock.
    #[cfg(test)]
    pub(crate) fn hsts_is_locked(&self) -> bool {
        self.0.hsts.try_lock().is_err()
    }

    /// The public suffix list.
    pub(crate) fn psl(&self) -> &PslCache {
        &self.0.psl
    }

    /// Keep alive its connections that have gone `interval` without, for
    /// a handle with no multi (`Curl_cpool_upkeep`): an idle one whose
    /// keep-alive fails closes through the share's own network, as the
    /// pool closes one when the share goes.
    pub(crate) fn upkeep(&self, interval: std::time::Duration, now: crate::time::Instant) {
        let mut net = lock(&self.0.net);
        let clock = self.0.clock();
        let mut exits = NoSet(&mut **net, clock, self.0.internal.get().cloned());
        self.pool().upkeep(interval, &mut exits, now);
    }

    /// Whether its sessions are going out; none before its first export.
    pub(crate) fn sessions_out(&self) -> Option<&SessionsOut> {
        self.0.sessions_out.get()
    }

    /// Whether its sessions are going out, made for an export.
    pub(crate) fn sessions_out_made(&self) -> Result<&SessionsOut, OutOfMemory> {
        if let Some(out) = self.0.sessions_out.get() {
            return Ok(out);
        }
        // Another thread's first export may have set one meanwhile, which
        // is then the one, and this one is let go.
        if let Err(lost) = self.0.sessions_out.set(SessionsOut::new()?) {
            drop(lost);
        }
        Ok(self.0.sessions_out.get().expect("set just now"))
    }

    /// The TLS sessions, locked; none if the share keeps none.
    pub(crate) fn sessions(&self) -> LockGuard<'_, Option<SessionCache>> {
        lock(&self.0.sessions)
    }
}

/// `mutex`, taken. No code panics holding one of the share's locks: a
/// panic aborts the process.
fn lock<T>(mutex: &Lock<T>) -> LockGuard<'_, T> {
    mutex.lock().expect("no panic holds a share's lock")
}

/// Watch the use of `kind` that `f` makes, telling `watch` around it, if
/// the share keeps that kind and the application watches.
pub(crate) fn watched<R>(
    watch: Option<&dyn ShareLock>,
    share: &Share,
    kind: Kind,
    f: impl FnOnce() -> R,
) -> R {
    let watch = watch.filter(|_| share.keeps(kind));
    if let Some(w) = watch {
        w.lock(kind, Access::Single);
    }
    let r = f();
    if let Some(w) = watch {
        w.unlock(kind);
    }
    r
}

impl fmt::Debug for Share {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Share")
    }
}

impl Inner {
    /// The clock of the multis that use it, the system's in a normal
    /// build: a goodbye's answer is waited for on it as the share's pool
    /// closes a connection with no multi (C's blocking disconnect).
    fn clock(&self) -> SharedClock {
        #[cfg(any(test, feature = "test-util"))]
        let clock = self.clock.get().cloned().unwrap_or(SharedClock::System);
        #[cfg(not(any(test, feature = "test-util")))]
        let clock = SharedClock::system();
        clock
    }
}

impl Drop for Inner {
    /// The share's idle connections close with it (`curl_share_cleanup`),
    /// each once its goodbye's answer is read, as C's disconnect blocks for
    /// it.
    fn drop(&mut self) {
        let clock = self.clock();
        let now = clock.now();
        let trace = self.internal.take();
        let net = self.net.get_mut().expect("no panic holds a share's lock");
        let pool = self.pool.get_mut().expect("no panic holds a share's lock");
        if let Some(t) = &trace {
            let n = pool.len();
            t.of(
                crate::components::Component::Multi,
                format_args!("[SHARE] [CPOOL] destroy, {n} connections"),
            );
        }
        pool.close_idle(&mut NoSet(&mut **net, clock, trace), now);
    }
}

/// A call told to a watch: the access of a lock, none for an unlock.
#[cfg(test)]
pub(crate) type Call = (Option<Access>, Kind);

/// A watch that records what it is told, and checks the share's own locks
/// are free each time: the application is told outside them.
#[cfg(test)]
#[derive(Clone)]
pub(crate) struct Told {
    share: Share,
    /// Each call in turn: the access of a lock, none for an unlock.
    told: std::sync::Arc<Lock<Vec<Call>>>,
}

#[cfg(test)]
impl Told {
    pub(crate) fn new(share: &Share) -> Told {
        Told {
            share: share.clone(),
            told: std::sync::Arc::default(),
        }
    }

    /// It, as a handle holds it.
    pub(crate) fn handler(&self) -> crate::handler::Handler<dyn ShareLock> {
        crate::handler::Handler::<dyn ShareLock>::new(self.clone(), |b| b).unwrap()
    }

    /// The uses told of since last asked, each a lock and its unlock.
    pub(crate) fn uses(&self) -> Vec<Kind> {
        let told = std::mem::take(&mut *lock(&self.told));
        assert!(
            told.chunks(2)
                .all(|c| matches!(c, [(Some(Access::Single), a), (None, b)] if a == b)),
            "{told:?}"
        );
        told.iter().step_by(2).map(|&(_, kind)| kind).collect()
    }

    /// Every call since last asked, in turn: the access of a lock, none
    /// for an unlock.
    pub(crate) fn calls(&self) -> Vec<Call> {
        std::mem::take(&mut *lock(&self.told))
    }

    fn record(&self, access: Option<Access>, kind: Kind) {
        let inner = &self.share.0;
        let free = inner.pool.try_lock().is_ok()
            && inner.dns.try_lock().is_ok()
            && inner.cookies.try_lock().is_ok()
            && inner.sessions.try_lock().is_ok()
            && inner.hsts.try_lock().is_ok()
            && !inner.psl.is_locked();
        assert!(free, "told of {kind:?} under the share's own lock");
        lock(&self.told).push((access, kind));
    }
}

#[cfg(test)]
impl ShareLock for Told {
    fn lock(&self, kind: Kind, access: Access) {
        self.record(Some(access), kind);
    }

    fn unlock(&self, kind: Kind) {
        self.record(None, kind);
    }
}

/// A watch that, told a use of `kind` begins, has the share stop keeping
/// it, as `Share::stop_keeping` on another thread would once its check
/// that no handle holds the share has passed and a handle has linked
/// since: the use finds the kind gone under the lock it then takes.
#[cfg(test)]
pub(crate) struct Emptying {
    pub(crate) told: Told,
    pub(crate) kind: Kind,
}

#[cfg(test)]
impl Emptying {
    pub(crate) fn handler(told: &Told, kind: Kind) -> crate::handler::Handler<dyn ShareLock> {
        let told = told.clone();
        crate::handler::Handler::<dyn ShareLock>::new(Emptying { told, kind }, |b| b).unwrap()
    }
}

#[cfg(test)]
impl ShareLock for Emptying {
    fn lock(&self, kind: Kind, access: Access) {
        if kind == self.kind {
            self.told.share.forget(kind);
        }
        self.told.lock(kind, access);
    }

    fn unlock(&self, kind: Kind) {
        self.told.unlock(kind);
    }
}

#[cfg(test)]
impl Share {
    /// Stop keeping `kind` as `stop_keeping` does, without its check that
    /// nothing else holds the share: the state its race with a handle
    /// linking leaves.
    pub(crate) fn forget(&self, kind: Kind) {
        self.let_go(kind);
    }
}

// What a share holds may move to whichever thread uses it next, and be
// used from several at once.
const _: () = {
    const fn shared<T: Send + Sync>() {}
    shared::<Share>();
};

#[cfg(test)]
mod tests {
    use super::*;

    /// A use of a kind it keeps is told as C locks every kind but the
    /// public suffixes: to itself. One it does not keep is not told.
    #[test]
    fn a_use_is_told_to_itself_and_only_of_what_is_kept() {
        let share = Share::new().unwrap();
        share.keep(Kind::Names).unwrap();
        let told = Told::new(&share);
        watched(Some(&told), &share, Kind::Names, || ());
        watched(Some(&told), &share, Kind::Cookies, || ());
        assert_eq!(
            told.calls(),
            [(Some(Access::Single), Kind::Names), (None, Kind::Names)]
        );
    }

    /// What a share keeps changes only while nothing else holds it
    /// (`CURLSHE_IN_USE`): each kind is kept and let go on its own, the
    /// cookies forgotten as they are.
    #[test]
    fn cookies_go_only_as_the_share_stops_keeping_them() {
        let share = Share::new().unwrap();
        share.keep(Kind::Cookies).unwrap();
        share.keep(Kind::Hsts).unwrap();
        let line = b"example.com\tFALSE\t/\tFALSE\t0\ta\t1";
        {
            let mut jar = share.cookies();
            let jar = jar.as_mut().unwrap();
            jar.add_line(line, None, 0, &mut 0).unwrap();
        }
        share.stop_keeping(Kind::Hsts).unwrap();
        let kept = share.cookies().as_ref().map(|j| j.listed().count());
        assert_eq!(kept, Some(1), "another kind let go");
        share.stop_keeping(Kind::Cookies).unwrap();
        share.keep(Kind::Cookies).unwrap();
        let kept = share.cookies().as_ref().map(|j| j.listed().count());
        assert_eq!(kept, Some(0), "kept again, empty");
    }

    #[test]
    fn what_is_kept_changes_only_while_the_share_is_idle() {
        let share = Share::new().unwrap();
        assert_eq!(share.holders(), 1);
        share.keep(Kind::Names).unwrap();
        share.keep(Kind::Cookies).unwrap();
        assert!(share.keeps(Kind::Names) && share.keeps(Kind::Cookies));
        assert!(!share.keeps(Kind::Connections));
        share.stop_keeping(Kind::Names).unwrap();
        assert!(!share.keeps(Kind::Names), "let go");
        assert!(share.keeps(Kind::Cookies), "the other kept");
        assert!(share.cookies().is_some(), "the jar kept with them");
        let held = share.clone();
        assert_eq!(share.holders(), 2);
        assert!(share.keep(Kind::Connections).is_err());
        assert!(share.stop_keeping(Kind::Cookies).is_err());
        assert!(held.keeps(Kind::Cookies), "unchanged while held");
        drop(held);
        assert_eq!(share.holders(), 1);
        share.stop_keeping(Kind::Cookies).unwrap();
        assert!(!share.keeps(Kind::Cookies));
        assert!(share.cookies().is_none(), "the jar forgotten");
        share.keep(Kind::SslSessions).unwrap();
        assert!(share.sessions().is_some(), "a cache made for them");
        assert!(share.keeps(Kind::SslSessions));
        share.stop_keeping(Kind::SslSessions).unwrap();
        assert!(share.sessions().is_none(), "the sessions forgotten");
        share.keep(Kind::Hsts).unwrap();
        assert!(share.keeps(Kind::Hsts) && share.hsts().is_some());
        share.stop_keeping(Kind::Hsts).unwrap();
        assert!(share.hsts().is_none(), "the HSTS cache forgotten");
        // What is let go is no longer kept, nor told of.
        let told = Told::new(&share);
        for kind in [Kind::Cookies, Kind::SslSessions, Kind::Hsts, Kind::Names] {
            assert!(!share.keeps(kind), "{kind:?}");
            watched(Some(&told), &share, kind, || ());
        }
        assert_eq!(told.calls(), []);
        assert_eq!(format!("{share:?}"), "Share");
    }
}
