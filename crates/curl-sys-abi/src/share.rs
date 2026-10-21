//! `CURLSH *`, the share (`lib/curl_share.c`).
//!
//! A `ShimShare` holds the core's `Share` and what C keeps beside it: the
//! kinds of data the application asked to share and its lock functions.
//! A handle given the share holds a clone of the core's, so the share is
//! in use while more than its own exists. The lock functions are called
//! for `CURL_LOCK_DATA_SHARE` as a handle is linked and unlinked, as C
//! calls them.

#![allow(unsafe_code)]

use core::cell::Cell;
use core::ffi::{c_int, c_void};
use core::ptr::{self, NonNull};

use curl_alloc::try_box;
use curl_core::share::Share;

use crate::easy::{EasyRef, ShimEasy};
use crate::ffi::{
    self, CURL, CURLSH, CURLSHE_BAD_OPTION, CURLSHE_IN_USE, CURLSHE_INVALID, CURLSHE_OK,
    CURLSHcode, CURLSHoption, curl_lock_data, curl_lock_function, curl_unlock_function,
};
use crate::setopt::function;

/// C's `CURL_GOOD_SHARE`, which tells a live share.
const MAGIC: u32 = 0x7e11_7a1e;

pub(crate) struct ShimShare {
    magic: Cell<u32>,
    core: Share,
    /// What it shares, a bit per `curl_lock_data` (`specifier`).
    kinds: Cell<u32>,
    lock: Cell<curl_lock_function>,
    unlock: Cell<curl_unlock_function>,
    user: Cell<*mut c_void>,
    /// A handle has been given it (`has_been_shared`).
    linked_once: Cell<bool>,
}

fn bit(data: curl_lock_data) -> u32 {
    1 << data.0
}

impl ShimShare {
    /// Whether a handle holds it.
    fn in_use(&self) -> bool {
        self.core.holders() > 1
    }

    /// Lock the share itself for `curl`, where both lock functions are
    /// set and, with no handle, a handle has been given it
    /// (`share_lock_acquire`); whether it was.
    fn lock_share(&self, curl: *mut CURL) -> bool {
        let (Some(lock), Some(_)) = (self.lock.get(), self.unlock.get()) else {
            return false;
        };
        if curl.is_null() && !self.linked_once.get() {
            return false;
        }
        // SAFETY: the application's lock function, called as C calls it.
        unsafe {
            lock(
                curl,
                ffi::CURL_LOCK_DATA_SHARE,
                ffi::CURL_LOCK_ACCESS_SINGLE,
                self.user.get(),
            );
        }
        true
    }

    fn unlock_share(&self, curl: *mut CURL, locked: bool) {
        if !locked {
            return;
        }
        if let Some(unlock) = self.unlock.get() {
            // SAFETY: as in `lock_share`.
            unsafe { unlock(curl, ffi::CURL_LOCK_DATA_SHARE, self.user.get()) };
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
    (sh.magic.get() == MAGIC).then_some(sh)
}

#[unsafe(no_mangle)]
pub extern "C" fn curl_share_init() -> *mut CURLSH {
    let Ok(core) = Share::new() else {
        return ptr::null_mut();
    };
    let shim = ShimShare {
        magic: Cell::new(MAGIC),
        core,
        kinds: Cell::new(bit(ffi::CURL_LOCK_DATA_SHARE)),
        lock: Cell::new(None),
        unlock: Cell::new(None),
        user: Cell::new(ptr::null_mut()),
        linked_once: Cell::new(false),
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
                    let kinds = sh.kinds.get();
                    sh.kinds.set(if on {
                        kinds | bit(data)
                    } else {
                        kinds & !bit(data)
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
            sh.lock.set(unsafe { function(p) });
            CURLSHE_OK
        }
        ffi::CURLSHOPT_UNLOCKFUNC => {
            // SAFETY: the application passes a pointer.
            let p = unsafe { args.next_arg::<*mut c_void>() };
            // SAFETY: it is an unlock function or NULL.
            sh.unlock.set(unsafe { function(p) });
            CURLSHE_OK
        }
        ffi::CURLSHOPT_USERDATA => {
            // SAFETY: the application passes a pointer.
            sh.user.set(unsafe { args.next_arg::<*mut c_void>() });
            CURLSHE_OK
        }
        _ => CURLSHE_BAD_OPTION,
    }
}
const _: ffi::proto::curl_share_setopt = curl_share_setopt;

/// Start or stop sharing `data`, as this build can.
fn kind(sh: &ShimShare, data: curl_lock_data, on: bool) -> CURLSHcode {
    match data {
        // Connections and names are kept in the share whatever is asked.
        ffi::CURL_LOCK_DATA_DNS | ffi::CURL_LOCK_DATA_CONNECT => CURLSHE_OK,
        ffi::CURL_LOCK_DATA_COOKIE if on => {
            sh.core.keep_cookies();
            CURLSHE_OK
        }
        ffi::CURL_LOCK_DATA_COOKIE => match sh.core.forget_cookies() {
            Ok(()) => CURLSHE_OK,
            // Lent only while a handle holds the share, refused above.
            Err(_) => unreachable!("not in use"),
        },
        // Each handle loads its own list; sharing it changes nothing a
        // transfer can see.
        ffi::CURL_LOCK_DATA_PSL if on => CURLSHE_OK,
        // HSTS and TLS sessions are not built in yet.
        ffi::CURL_LOCK_DATA_HSTS | ffi::CURL_LOCK_DATA_SSL_SESSION => ffi::CURLSHE_NOT_BUILT_IN,
        _ => CURLSHE_BAD_OPTION,
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
    shim.magic.set(0);
    // SAFETY: the share came from `Box::leak` in `curl_share_init`, no
    // handle holds it, and the caller does not use it again. The lock
    // functions are copied out before it goes.
    let gone = unsafe { Box::from_raw(sh.cast::<ShimShare>()) };
    let (unlock, user) = (gone.unlock.get(), gone.user.get());
    drop(gone);
    if locked && let Some(unlock) = unlock {
        // SAFETY: as in `lock_share`.
        unsafe { unlock(ptr::null_mut(), ffi::CURL_LOCK_DATA_SHARE, user) };
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
    let linked = set_core(easy, Some(new.core.clone()));
    if linked.is_ok() {
        easy.share.set(Some(NonNull::from(new)));
        new.linked_once.set(true);
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
fn set_core(easy: &ShimEasy, share: Option<Share>) -> Result<(), Refused> {
    match easy.with_easy(|e| match e {
        EasyRef::Easy(e) => {
            e.set_share(share);
            Ok(())
        }
        EasyRef::Frame(..) => Err(Refused),
    }) {
        Ok(set) => set,
        Err(_) => Err(Refused),
    }
}

/// The handle's transfer cannot be reached: a callback of its own runs.
#[derive(Debug)]
pub(crate) struct Refused;
