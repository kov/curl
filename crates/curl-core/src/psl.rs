//! The public suffix list a transfer's cookies are checked against
//! (`lib/psl.c`): kept by its share if that keeps it, else by its multi,
//! loaded when first asked and again once it is 72 hours old.
//!
//! The application is told of each use (`CURL_LOCK_DATA_PSL`) as C locks
//! it, inside the jar's use where the share keeps cookies too. The jar's
//! mutex is held as the list is asked, so the tells are kept and made once
//! that is let go, before the jar's own unlock: the application sees C's
//! order, and is never called under one of the share's own locks.

use std::cell::RefCell;
use std::fmt;
use std::sync::Mutex;
use std::time::Duration;

use curl_alloc::{OutOfMemory, TryVec as _};

use crate::cookie::{PublicSuffixes, SuffixCheck, Suffixes};
use crate::handler::Handler;
use crate::share::{Access, Kind, Share, ShareLock};
use crate::time::Instant;

/// How long a list is used before it is loaded again (`PSL_TTL`).
const TTL: Duration = Duration::from_secs(72 * 3600);

/// Where lists come from (libpsl, which the core does not link).
pub trait SuffixLibrary: Send + Sync {
    /// The latest list the system has, a new one each time, if it has one
    /// (`psl_latest`).
    fn latest(&self) -> Option<Suffixes>;

    /// The list built into the library, if it was built with one
    /// (`psl_builtin`).
    fn builtin(&self) -> Option<Suffixes>;
}

impl fmt::Debug for dyn SuffixLibrary {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SuffixLibrary")
    }
}

/// A list, kept for those using it (`struct PslCache`).
pub(crate) struct PslCache(Mutex<Loaded>);

struct Loaded {
    list: Option<Suffixes>,
    /// The list is the latest the system had, not the library's own.
    latest: bool,
    expires: Instant,
}

impl Default for PslCache {
    fn default() -> PslCache {
        PslCache(Mutex::new(Loaded {
            list: None,
            latest: false,
            expires: Instant::EPOCH,
        }))
    }
}

impl PslCache {
    /// Whether it is in use now, for the tests of what runs out of its
    /// lock.
    #[cfg(test)]
    pub(crate) fn is_locked(&self) -> bool {
        self.0.try_lock().is_err()
    }

    /// The list at `now`, and whether it had to be looked for: there was
    /// none, or it had expired (`Curl_psl_use`). The latest the system has
    /// takes its place, or else the library's own, unless it is itself the
    /// latest the system had, which is kept and looked for again next time.
    fn at(&self, library: &dyn SuffixLibrary, now: Instant) -> (Option<Suffixes>, bool) {
        let mut loaded = self.0.lock().expect("no panic holds it");
        if loaded.list.is_some() && loaded.expires > now {
            return (loaded.list.clone(), false);
        }
        let latest = library.latest();
        let is_latest = latest.is_some();
        let list = match latest {
            Some(list) => Some(list),
            None if loaded.latest => None,
            None => library.builtin(),
        };
        if list.is_some() {
            loaded.list = list;
            loaded.latest = is_latest;
            loaded.expires = now.after(TTL);
        }
        (loaded.list.clone(), true)
    }
}

/// Where a transfer's list is kept.
enum Home<'a> {
    Multi(&'a PslCache),
    Share(Share),
}

/// A transfer's use of its list, for the jar to ask it as each cookie
/// needs, and then to tell the application of.
pub(crate) struct PslUse<'a> {
    home: Home<'a>,
    library: &'static dyn SuffixLibrary,
    now: Instant,
    /// Told of each use, where the share keeps the list and the
    /// application watches it.
    watch: Option<Handler<dyn ShareLock>>,
    /// Each use the application is yet to be told of: whether it looked for
    /// a list. None could be kept, for want of memory, if `None`.
    untold: RefCell<Option<Vec<bool>>>,
}

impl<'a> PslUse<'a> {
    /// The use a transfer makes of the list `library` loads, at `now`:
    /// `share`'s, the share it is kept in, if any, else `multi`'s.
    pub(crate) fn new(
        share: Option<&Share>,
        watch: Option<&Handler<dyn ShareLock>>,
        multi: &'a PslCache,
        library: &'static dyn SuffixLibrary,
        now: Instant,
    ) -> PslUse<'a> {
        let (home, watch) = match share {
            Some(share) => (Home::Share(share.clone()), watch.cloned()),
            None => (Home::Multi(multi), None),
        };
        PslUse {
            home,
            library,
            now,
            watch,
            untold: RefCell::new(Some(Vec::new())),
        }
    }

    /// Tell the application of each use made, in turn: the list read, and
    /// when it was looked for, let go to be had alone first
    /// (`Curl_psl_use`, `Curl_psl_release`).
    pub(crate) fn tell(&self) -> Result<(), OutOfMemory> {
        let untold = self.untold.borrow_mut().as_mut().map(std::mem::take);
        let Some(untold) = untold else {
            return Err(OutOfMemory);
        };
        let Some(watch) = &self.watch else {
            return Ok(());
        };
        let one = |access| {
            watch.lock(Kind::Psl, access);
            watch.unlock(Kind::Psl);
        };
        for looked_for in untold {
            if looked_for {
                one(Access::Shared);
                one(Access::Single);
            }
            one(Access::Shared);
        }
        Ok(())
    }
}

impl SuffixCheck for PslUse<'_> {
    fn with_list(&self, ask: &mut dyn FnMut(Option<&dyn PublicSuffixes>)) {
        let cache = match &self.home {
            Home::Multi(cache) => *cache,
            Home::Share(share) => share.psl(),
        };
        let (list, looked_for) = cache.at(self.library, self.now);
        if self.watch.is_some() {
            let mut untold = self.untold.borrow_mut();
            let kept = untold.as_mut().map(|u| u.try_push(looked_for));
            if matches!(kept, Some(Err(OutOfMemory))) {
                *untold = None;
            }
        }
        ask(list.as_ref().map(Suffixes::list));
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicU32, AtomicUsize, Ordering};

    use super::*;

    struct Nothing;

    impl PublicSuffixes for Nothing {
        fn is_public_suffix(&self, _: &[u8]) -> bool {
            false
        }

        fn accepts(&self, _: &[u8], _: &[u8]) -> bool {
            true
        }
    }

    /// Counts what it is asked for, and gives what it is set to.
    #[derive(Default)]
    struct Library {
        latest: AtomicU32,
        builtin: AtomicU32,
        has_latest: AtomicUsize,
        has_builtin: AtomicUsize,
    }

    impl SuffixLibrary for Library {
        fn latest(&self) -> Option<Suffixes> {
            self.latest.fetch_add(1, Ordering::Relaxed);
            (self.has_latest.load(Ordering::Relaxed) != 0)
                .then(|| Suffixes::new(Box::new(Nothing)).unwrap())
        }

        fn builtin(&self) -> Option<Suffixes> {
            self.builtin.fetch_add(1, Ordering::Relaxed);
            (self.has_builtin.load(Ordering::Relaxed) != 0)
                .then(|| Suffixes::new(Box::new(Nothing)).unwrap())
        }
    }

    impl Library {
        fn set(&self, latest: bool, builtin: bool) {
            self.has_latest.store(latest.into(), Ordering::Relaxed);
            self.has_builtin.store(builtin.into(), Ordering::Relaxed);
        }

        fn asked(&self) -> (u32, u32) {
            (
                self.latest.swap(0, Ordering::Relaxed),
                self.builtin.swap(0, Ordering::Relaxed),
            )
        }
    }

    const HOUR: Duration = Duration::from_secs(3600);

    /// A list is kept for just under 72 hours, and looked for at exactly
    /// 72, from when it was loaded (`expires <= now`).
    #[test]
    fn a_list_is_looked_for_again_at_exactly_its_time() {
        let library = Library::default();
        library.set(true, false);
        let cache = PslCache::default();
        let start = Instant::EPOCH.after(HOUR);
        let (first, looked) = cache.at(&library, start);
        assert!(first.is_some() && looked);
        assert_eq!(library.asked(), (1, 0));
        let before = start.after(72 * HOUR - Duration::from_secs(1));
        let (kept, looked) = cache.at(&library, before);
        assert!(kept.is_some() && !looked);
        assert_eq!(library.asked(), (0, 0));
        let at = start.after(72 * HOUR);
        let (_, looked) = cache.at(&library, at);
        assert!(looked);
        assert_eq!(library.asked(), (1, 0));
        // The time runs from the new load.
        let (_, looked) = cache.at(&library, at.after(71 * HOUR));
        assert!(!looked);
        assert_eq!(library.asked(), (0, 0));
    }

    /// The library's own list is had only if the system has none and what
    /// is kept is not the system's: a system's list that has gone stays,
    /// past its time, and the system is asked at each use from then on.
    #[test]
    fn a_list_goes_only_for_one_at_least_as_good() {
        let library = Library::default();
        library.set(false, true);
        let cache = PslCache::default();
        let start = Instant::EPOCH.after(HOUR);
        let (list, looked) = cache.at(&library, start);
        assert!(list.is_some() && looked);
        assert_eq!(
            library.asked(),
            (1, 1),
            "the library's own, for want of one"
        );
        // The library's own is looked for again at its time.
        let (_, looked) = cache.at(&library, start.after(72 * HOUR));
        assert!(looked);
        assert_eq!(library.asked(), (1, 1));
        // The system's replaces it, and the library's is not asked for.
        library.set(true, true);
        let at = start.after(144 * HOUR);
        cache.at(&library, at);
        assert_eq!(library.asked(), (1, 0));
        // Gone at its time, it is kept and its time does not start again.
        library.set(false, true);
        let later = at.after(72 * HOUR);
        let (list, looked) = cache.at(&library, later);
        assert!(list.is_some() && looked);
        assert_eq!(library.asked(), (1, 0), "kept: the system's is better");
        let (_, looked) = cache.at(&library, later);
        assert!(looked, "still past its time");
        assert_eq!(library.asked(), (1, 0));
    }

    /// With neither, there is no list: the jar refuses for want of it.
    #[test]
    fn no_list_is_had_from_a_library_with_none() {
        let library = Library::default();
        let cache = PslCache::default();
        let (list, looked) = cache.at(&library, Instant::EPOCH);
        assert!(list.is_none() && looked);
        let (list, looked) = cache.at(&library, Instant::EPOCH);
        assert!(list.is_none() && looked, "looked for at each use");
        assert_eq!(library.asked(), (2, 2));
    }
}
