//! `CURLSH *`, the share (`lib/curl_share.c`).
//!
//! A `ShimShare` holds the core's `Share` and what C keeps beside it: the
//! kinds of data the application asked to share and its lock functions.
//! A handle given the share holds a clone of the core's, so the share is
//! in use while more than its own exists. The lock functions are called
//! for `CURL_LOCK_DATA_SHARE` as a handle is linked and unlinked, and,
//! through the watch the core is given with the share, around each use a
//! handle's transfer makes of what is shared, as C calls them.

#![allow(unsafe_code)]

use core::ffi::{c_int, c_void};
use core::ptr::{self, NonNull};
use core::sync::atomic::{AtomicU32, Ordering};
use std::sync::Mutex;

use curl_alloc::try_box;
use curl_core::handler::Handler;
use curl_core::share::{Kind, Share, ShareLock};

use crate::easy::{EasyRef, ShimEasy};
use crate::ffi::{
    self, CURL, CURLSH, CURLSHE_BAD_OPTION, CURLSHE_IN_USE, CURLSHE_INVALID, CURLSHE_OK,
    CURLSHcode, CURLSHoption, curl_lock_data, curl_lock_function, curl_unlock_function,
};
use crate::setopt::function;

/// C's `CURL_GOOD_SHARE`, which tells a live share.
const MAGIC: u32 = 0x7e11_7a1e;

/// A share as C's functions reach it: from any thread, at once, so what
/// C keeps beside the core's share is behind a lock of its own, held only
/// to read or change it, never across a call to the application.
pub(crate) struct ShimShare {
    magic: AtomicU32,
    core: Share,
    settings: Mutex<Settings>,
}

#[derive(Clone, Copy)]
struct Settings {
    /// What it shares, a bit per `curl_lock_data` (`specifier`).
    kinds: u32,
    lock: curl_lock_function,
    unlock: curl_unlock_function,
    user: *mut c_void,
    /// A handle has been given it (`has_been_shared`).
    linked_once: bool,
}

// SAFETY: `user` is the application's, only handed back to its own lock
// functions, which C calls from whichever thread uses the share; the
// application, which shares the share across threads, makes them fit to
// be.
unsafe impl Send for Settings {}

fn bit(data: curl_lock_data) -> u32 {
    1 << data.0
}

impl ShimShare {
    /// What C keeps beside the core's share, as it is now.
    fn settings(&self) -> Settings {
        *self.settings.lock().expect("no panic holds it")
    }

    fn change(&self, f: impl FnOnce(&mut Settings)) {
        f(&mut self.settings.lock().expect("no panic holds it"));
    }

    /// Whether a handle holds it.
    fn in_use(&self) -> bool {
        self.core.holders() > 1
    }

    /// Lock the share itself for `curl`, where both lock functions are
    /// set and, with no handle, a handle has been given it
    /// (`share_lock_acquire`); whether it was.
    fn lock_share(&self, curl: *mut CURL) -> bool {
        let set = self.settings();
        let (Some(lock), Some(_)) = (set.lock, set.unlock) else {
            return false;
        };
        if curl.is_null() && !set.linked_once {
            return false;
        }
        // SAFETY: the application's lock function, called as C calls it.
        unsafe {
            lock(
                curl,
                ffi::CURL_LOCK_DATA_SHARE,
                ffi::CURL_LOCK_ACCESS_SINGLE,
                set.user,
            );
        }
        true
    }

    fn unlock_share(&self, curl: *mut CURL, locked: bool) {
        if !locked {
            return;
        }
        let set = self.settings();
        if let Some(unlock) = set.unlock {
            // SAFETY: as in `lock_share`.
            unsafe { unlock(curl, ffi::CURL_LOCK_DATA_SHARE, set.user) };
        }
    }
}

/// The share `sh` points to, if it is one.
///
/// # Safety
///
/// `sh` is NULL or a pointer `curl_share_init` returned, not cleaned up.
unsafe fn share<'a>(sh: *mut CURLSH) -> Option<&'a ShimShare> {
    let sh = NonNull::new(sh.cast::<ShimShare>())?;
    // SAFETY: as the caller guarantees.
    let sh = unsafe { sh.as_ref() };
    (sh.magic.load(Ordering::Acquire) == MAGIC).then_some(sh)
}

#[unsafe(no_mangle)]
pub extern "C" fn curl_share_init() -> *mut CURLSH {
    let Ok(core) = Share::new() else {
        return ptr::null_mut();
    };
    let shim = ShimShare {
        magic: AtomicU32::new(MAGIC),
        core,
        settings: Mutex::new(Settings {
            kinds: bit(ffi::CURL_LOCK_DATA_SHARE),
            lock: None,
            unlock: None,
            user: ptr::null_mut(),
            linked_once: false,
        }),
    };
    match try_box(shim) {
        Ok(shim) => Box::leak(shim) as *mut ShimShare as *mut CURLSH,
        Err(_) => ptr::null_mut(),
    }
}
const _: ffi::proto::curl_share_init = curl_share_init;

/// # Safety
///
/// `sh` is NULL or a live share; the argument is of the option's type.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn curl_share_setopt(
    sh: *mut CURLSH,
    option: CURLSHoption,
    mut args: ...
) -> CURLSHcode {
    // SAFETY: as the caller guarantees.
    let Some(sh) = (unsafe { share(sh) }) else {
        return CURLSHE_INVALID;
    };
    // No option changes while a handle holds it.
    if sh.in_use() {
        return CURLSHE_IN_USE;
    }
    match option {
        ffi::CURLSHOPT_SHARE | ffi::CURLSHOPT_UNSHARE => {
            // SAFETY: the application passes an int, the type of each.
            let data = curl_lock_data(unsafe { args.next_arg::<c_int>() } as _);
            let on = option == ffi::CURLSHOPT_SHARE;
            match kind(sh, data, on) {
                CURLSHE_OK => {
                    sh.change(|set| match on {
                        true => set.kinds |= bit(data),
                        false => set.kinds &= !bit(data),
                    });
                    CURLSHE_OK
                }
                refused => refused,
            }
        }
        ffi::CURLSHOPT_LOCKFUNC => {
            // SAFETY: the application passes a pointer.
            let p = unsafe { args.next_arg::<*mut c_void>() };
            // SAFETY: it is a lock function or NULL.
            let lock = unsafe { function(p) };
            sh.change(|set| set.lock = lock);
            CURLSHE_OK
        }
        ffi::CURLSHOPT_UNLOCKFUNC => {
            // SAFETY: the application passes a pointer.
            let p = unsafe { args.next_arg::<*mut c_void>() };
            // SAFETY: it is an unlock function or NULL.
            let unlock = unsafe { function(p) };
            sh.change(|set| set.unlock = unlock);
            CURLSHE_OK
        }
        ffi::CURLSHOPT_USERDATA => {
            // SAFETY: the application passes a pointer.
            let user = unsafe { args.next_arg::<*mut c_void>() };
            sh.change(|set| set.user = user);
            CURLSHE_OK
        }
        _ => CURLSHE_BAD_OPTION,
    }
}
const _: ffi::proto::curl_share_setopt = curl_share_setopt;

/// Start or stop sharing `data`, as this build can.
fn kind(sh: &ShimShare, data: curl_lock_data, on: bool) -> CURLSHcode {
    match data {
        ffi::CURL_LOCK_DATA_DNS | ffi::CURL_LOCK_DATA_CONNECT | ffi::CURL_LOCK_DATA_COOKIE => {
            let kind = core_kind(data).expect("one the core keeps");
            let kept = match on {
                true => sh.core.keep(kind),
                false => sh.core.stop_keeping(kind),
            };
            kept.expect("no handle holds it, checked above");
            CURLSHE_OK
        }
        // Each handle loads its own list; sharing it changes nothing a
        // transfer can see.
        ffi::CURL_LOCK_DATA_PSL if on => CURLSHE_OK,
        // HSTS and TLS sessions are not built in yet.
        ffi::CURL_LOCK_DATA_HSTS | ffi::CURL_LOCK_DATA_SSL_SESSION => ffi::CURLSHE_NOT_BUILT_IN,
        _ => CURLSHE_BAD_OPTION,
    }
}

/// The kind of data the core keeps for `data`, if it keeps it.
fn core_kind(data: curl_lock_data) -> Option<Kind> {
    match data {
        ffi::CURL_LOCK_DATA_CONNECT => Some(Kind::Connections),
        ffi::CURL_LOCK_DATA_DNS => Some(Kind::Names),
        ffi::CURL_LOCK_DATA_COOKIE => Some(Kind::Cookies),
        _ => None,
    }
}

/// The application's lock functions, called with the handle `curl`
/// around each use its transfer makes of what is shared
/// (`Curl_share_lock`, `Curl_share_unlock`).
struct LockCalls {
    curl: *mut CURL,
    lock: curl_lock_function,
    unlock: curl_unlock_function,
    user: *mut c_void,
}

fn lock_data(kind: Kind) -> curl_lock_data {
    match kind {
        Kind::Connections => ffi::CURL_LOCK_DATA_CONNECT,
        Kind::Names => ffi::CURL_LOCK_DATA_DNS,
        Kind::Cookies => ffi::CURL_LOCK_DATA_COOKIE,
    }
}

// SAFETY: the lock functions and their userdata are the application's,
// made for the share's use from any thread (`CURLSHOPT_LOCKFUNC`); the
// handle is passed back, never reached.
unsafe impl Send for LockCalls {}
// SAFETY: as for `Send`: shared, it is only read.
unsafe impl Sync for LockCalls {}

impl ShareLock for LockCalls {
    fn lock(&self, kind: Kind) {
        if let Some(lock) = self.lock {
            // SAFETY: the application's lock function, called as C calls
            // it, with the handle it was given for, which outlives its
            // link to the share.
            unsafe {
                lock(
                    self.curl,
                    lock_data(kind),
                    ffi::CURL_LOCK_ACCESS_SINGLE,
                    self.user,
                )
            };
        }
    }

    fn unlock(&self, kind: Kind) {
        if let Some(unlock) = self.unlock {
            // SAFETY: as in `lock`.
            unsafe { unlock(self.curl, lock_data(kind), self.user) };
        }
    }
}

/// # Safety
///
/// `sh` is NULL or a live share, not used again if this succeeds.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn curl_share_cleanup(sh: *mut CURLSH) -> CURLSHcode {
    // SAFETY: as the caller guarantees.
    let Some(shim) = (unsafe { share(sh) }) else {
        return CURLSHE_INVALID;
    };
    if shim.in_use() {
        return CURLSHE_IN_USE;
    }
    let locked = shim.lock_share(ptr::null_mut());
    shim.magic.store(0, Ordering::Release);
    // SAFETY: the share came from `Box::leak` in `curl_share_init`, no
    // handle holds it, and the caller does not use it again. The lock
    // functions are copied out before it goes.
    let gone = unsafe { Box::from_raw(sh.cast::<ShimShare>()) };
    let Settings {
        kinds,
        lock,
        unlock,
        user,
        ..
    } = gone.settings();
    let connections = kinds & bit(ffi::CURL_LOCK_DATA_CONNECT) != 0;
    if locked && let Some(unlock) = unlock {
        // SAFETY: as in `lock_share`.
        unsafe { unlock(ptr::null_mut(), ffi::CURL_LOCK_DATA_SHARE, user) };
    }
    // Its connections close under their lock (`Curl_cpool_destroy`), told
    // with no handle where C gives its share's own.
    let locks = LockCalls {
        curl: ptr::null_mut(),
        lock,
        unlock,
        user,
    };
    if connections {
        locks.lock(Kind::Connections);
    }
    drop(gone);
    if connections {
        locks.unlock(Kind::Connections);
    }
    CURLSHE_OK
}
const _: ffi::proto::curl_share_cleanup = curl_share_cleanup;

/// Give the handle `easy` the share `sh`, or none if NULL, in place of the
/// one it has (`setopt_share`): unlinked from the old under its lock, then
/// linked to the new under its own. A pointer that is no share leaves the
/// handle with none, as in C.
///
/// # Safety
///
/// `sh` is NULL or a pointer `curl_share_init` returned.
pub(crate) unsafe fn set(easy: &ShimEasy, sh: *mut CURLSH) -> Result<(), Refused> {
    unlink(easy)?;
    // SAFETY: as the caller guarantees.
    let Some(new) = (unsafe { share(sh) }) else {
        return Ok(());
    };
    let curl = easy.as_curl();
    let locked = new.lock_share(curl);
    let linked = set_core(easy, Some(new));
    if linked.is_ok() {
        easy.share.set(Some(NonNull::from(new)));
        new.change(|set| set.linked_once = true);
    }
    new.unlock_share(curl, locked);
    linked
}

/// Take the handle `easy` off its share, if it has one
/// (`Curl_share_easy_unlink`).
pub(crate) fn unlink(easy: &ShimEasy) -> Result<(), Refused> {
    let Some(old) = easy.share.get() else {
        return Ok(());
    };
    // SAFETY: a share outlives the handles holding it: cleanup refuses it
    // while they do.
    let old = unsafe { old.as_ref() };
    let curl = easy.as_curl();
    let locked = old.lock_share(curl);
    let unlinked = set_core(easy, None);
    if unlinked.is_ok() {
        easy.share.set(None);
    }
    old.unlock_share(curl, locked);
    unlinked
}

/// Give the handle's transfer `share`, unless a callback of its own runs,
/// when it has a connection in C and the change is refused.
/// The share's lock functions, if any is set, are told of the uses it
/// makes of what is shared.
fn set_core(easy: &ShimEasy, share: Option<&ShimShare>) -> Result<(), Refused> {
    let watch = match share {
        Some(sh) if sh.settings().lock.is_some() || sh.settings().unlock.is_some() => {
            let set = sh.settings();
            let calls = LockCalls {
                curl: easy.as_curl(),
                lock: set.lock,
                unlock: set.unlock,
                user: set.user,
            };
            let calls: Box<dyn ShareLock> = try_box(calls).map_err(|_| Refused::OutOfMemory)?;
            Some(Handler::new(calls).map_err(|_| Refused::OutOfMemory)?)
        }
        _ => None,
    };
    match easy.with_easy(|e| match e {
        EasyRef::Easy(e) => {
            match (share, watch) {
                (Some(sh), Some(watch)) => e.set_share_watched(sh.core.clone(), watch),
                (sh, _) => e.set_share(sh.map(|sh| sh.core.clone())),
            }
            Ok(())
        }
        EasyRef::Frame(..) => Err(Refused::Running),
    }) {
        Ok(set) => set,
        Err(_) => Err(Refused::Running),
    }
}

/// Why the handle's share was not changed.
#[derive(Debug)]
pub(crate) enum Refused {
    /// The handle's transfer cannot be reached: a callback of its own
    /// runs.
    Running,
    OutOfMemory,
}

// C's share functions may be called from several threads at once.
const _: () = {
    const fn shared<T: Send + Sync>() {}
    shared::<ShimShare>();
};
