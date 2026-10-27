//! The share: connections, resolved names, cookies and TLS sessions kept
//! for every transfer given it, whichever handle and thread runs them
//! (`CURLSH`, with `CURL_LOCK_DATA_CONNECT`, `CURL_LOCK_DATA_DNS`,
//! `CURL_LOCK_DATA_COOKIE` and `CURL_LOCK_DATA_SSL_SESSION`).
//!
//! Each kind of data it keeps has a lock of its own, held for one use of
//! it at a time (a search for a connection, a lookup, a cookie stored) and
//! never across a callback, so no transfer waits on another's. A
//! connection a transfer uses is its lease's, not the share's, until it
//! is given back. The application may watch every use, as C calls its
//! lock functions: its `ShareLock` is told before the lock is taken and
//! after it is let go.

use std::fmt;
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::{Mutex, MutexGuard};

use curl_alloc::{OutOfMemory, TryArc, try_box};

use crate::conn::io::{Net, SystemNet};
use crate::conn::shutdown::NoSet;
use crate::conn::{DnsCache, Pool};
use crate::cookie::Jar;
use crate::tls::SessionCache;

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
}

impl Kind {
    fn bit(self) -> u8 {
        match self {
            Kind::Connections => 1,
            Kind::Names => 2,
            Kind::Cookies => 4,
            Kind::SslSessions => 8,
        }
    }
}

/// Told around each use of what a transfer's share keeps, as C calls the
/// share's lock functions with the transfer's handle
/// (`CURLSHOPT_LOCKFUNC`, `CURLSHOPT_UNLOCKFUNC`). The share's own locks
/// guard the data; this lets the application see each use.
pub trait ShareLock: Send + Sync {
    fn lock(&self, kind: Kind);
    fn unlock(&self, kind: Kind);
}

/// A share, cloned to give it to another handle.
#[derive(Clone)]
pub struct Share(TryArc<Inner>);

struct Inner {
    /// The kinds it keeps, a bit each.
    keeps: AtomicU8,
    pool: Mutex<Pool>,
    dns: Mutex<DnsCache>,
    /// The jar, made when cookies are first kept.
    cookies: Mutex<Option<Jar>>,
    /// The TLS sessions, a cache made when they are first kept.
    sessions: Mutex<Option<SessionCache>>,
    /// What the connections left idle at the end are closed through, as
    /// C's share closes them through its own internal handle.
    net: Mutex<Box<dyn Net + Send>>,
}

/// A handle holds the share, so what it keeps cannot change.
#[derive(Debug)]
pub struct InUse;

impl Share {
    /// A share keeping nothing yet, whose connections are the system's.
    pub fn new() -> Result<Share, OutOfMemory> {
        Share::with_net(try_box(SystemNet::default())?)
    }

    /// A share keeping nothing yet, whose connections are `net`'s.
    pub fn with_net(net: Box<dyn Net + Send>) -> Result<Share, OutOfMemory> {
        Ok(Share(TryArc::try_new(Inner {
            keeps: AtomicU8::new(0),
            pool: Mutex::new(Pool::new()?),
            dns: Mutex::new(DnsCache::default()),
            cookies: Mutex::new(None),
            sessions: Mutex::new(None),
            net: Mutex::new(net),
        })?))
    }

    /// Keep `kind` for the transfers given the share from now on
    /// (`CURLSHOPT_SHARE`): cookies in one jar for them all, each
    /// transfer whose own options turn its jar on using the share's in
    /// its place; TLS sessions in a cache of 25 peers, in place of each
    /// transfer's multi's.
    pub fn keep(&self, kind: Kind) -> Result<(), InUse> {
        self.idle()?;
        if kind == Kind::Cookies {
            let mut jar = lock(&self.0.cookies);
            if jar.is_none() {
                *jar = Some(Jar::default());
            }
        }
        if kind == Kind::SslSessions {
            let mut sessions = lock(&self.0.sessions);
            if sessions.is_none() {
                *sessions = Some(SessionCache::new(SessionCache::PEERS));
            }
        }
        self.0.keeps.fetch_or(kind.bit(), Ordering::Relaxed);
        Ok(())
    }

    /// Keep `kind` no more (`CURLSHOPT_UNSHARE`), forgetting the cookies
    /// or TLS sessions kept; connections and names stay until the share
    /// goes, as C's do.
    pub fn stop_keeping(&self, kind: Kind) -> Result<(), InUse> {
        self.idle()?;
        if kind == Kind::Cookies {
            *lock(&self.0.cookies) = None;
        }
        if kind == Kind::SslSessions {
            *lock(&self.0.sessions) = None;
        }
        self.0.keeps.fetch_and(!kind.bit(), Ordering::Relaxed);
        Ok(())
    }

    /// Whether the share keeps `kind`.
    pub fn keeps(&self, kind: Kind) -> bool {
        self.0.keeps.load(Ordering::Relaxed) & kind.bit() != 0
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
    pub(crate) fn pool(&self) -> MutexGuard<'_, Pool> {
        lock(&self.0.pool)
    }

    /// Whether its pool is locked now, for the tests of what runs out of
    /// the lock.
    #[cfg(test)]
    pub(crate) fn pool_is_locked(&self) -> bool {
        self.0.pool.try_lock().is_err()
    }

    /// The names kept, locked.
    pub(crate) fn dns(&self) -> MutexGuard<'_, DnsCache> {
        lock(&self.0.dns)
    }

    /// The jar, locked; none if the share keeps no cookies.
    pub(crate) fn cookies(&self) -> MutexGuard<'_, Option<Jar>> {
        lock(&self.0.cookies)
    }

    /// Keep alive its connections that have gone `interval` without, for
    /// a handle with no multi (`Curl_cpool_upkeep`): an idle one whose
    /// keep-alive fails closes through the share's own network, as the
    /// pool closes one when the share goes.
    pub(crate) fn upkeep(&self, interval: std::time::Duration, now: crate::time::Instant) {
        let mut net = lock(&self.0.net);
        self.pool().upkeep(interval, &mut NoSet(&mut **net), now);
    }

    /// The TLS sessions, locked; none if the share keeps none.
    pub(crate) fn sessions(&self) -> MutexGuard<'_, Option<SessionCache>> {
        lock(&self.0.sessions)
    }
}

/// `mutex`, taken. No code panics holding one of the share's locks: a
/// panic aborts the process.
fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
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
        w.lock(kind);
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

impl Drop for Inner {
    /// The share's idle connections close with it (`curl_share_cleanup`).
    fn drop(&mut self) {
        let net = self.net.get_mut().expect("no panic holds a share's lock");
        self.pool
            .get_mut()
            .expect("no panic holds a share's lock")
            // With no clock, the one try of each shutdown is in time.
            .close_idle(&mut NoSet(&mut **net), crate::time::Instant::EPOCH);
    }
}

/// A watch that records what it is told, and checks the share's own locks
/// are free each time: the application is told outside them.
#[cfg(test)]
#[derive(Clone)]
pub(crate) struct Told {
    share: Share,
    told: std::sync::Arc<Mutex<Vec<(bool, Kind)>>>,
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
        let watch: Box<dyn ShareLock> = Box::new(self.clone());
        crate::handler::Handler::new(watch).unwrap()
    }

    /// The uses told of since last asked, each a lock and its unlock.
    pub(crate) fn uses(&self) -> Vec<Kind> {
        let told = std::mem::take(&mut *lock(&self.told));
        assert!(
            told.chunks(2)
                .all(|c| matches!(c, [(true, a), (false, b)] if a == b)),
            "{told:?}"
        );
        told.iter().step_by(2).map(|&(_, kind)| kind).collect()
    }

    fn record(&self, locked: bool, kind: Kind) {
        let inner = &self.share.0;
        let free = inner.pool.try_lock().is_ok()
            && inner.dns.try_lock().is_ok()
            && inner.cookies.try_lock().is_ok()
            && inner.sessions.try_lock().is_ok();
        assert!(free, "told of {kind:?} under the share's own lock");
        lock(&self.told).push((locked, kind));
    }
}

#[cfg(test)]
impl ShareLock for Told {
    fn lock(&self, kind: Kind) {
        self.record(true, kind);
    }

    fn unlock(&self, kind: Kind) {
        self.record(false, kind);
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

    /// What a share keeps changes only while nothing else holds it
    /// (`CURLSHE_IN_USE`): each kind is kept and let go on its own, the
    /// cookies forgotten as they are.
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
        share.stop_keeping(Kind::SslSessions).unwrap();
        assert!(share.sessions().is_none(), "the sessions forgotten");
        assert_eq!(format!("{share:?}"), "Share");
    }
}
