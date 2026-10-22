//! The share: connections and resolved names kept for every transfer
//! given it, whichever handle runs them (`CURLSH`, with
//! `CURL_LOCK_DATA_CONNECT` and `CURL_LOCK_DATA_DNS`), and the cookies if
//! it is asked to keep them (`CURL_LOCK_DATA_COOKIE`).
//!
//! A transfer's multi borrows the caches whole for the length of a
//! perform, and a handle the cookie jar for one operation on it, and they
//! give them back at its end: one owner at a time, so no lock guards
//! them. A perform on a share already lent is refused.

use std::cell::RefCell;
use std::fmt;

use curl_alloc::{OutOfMemory, TryRc, try_box};

use crate::conn::Caches;
use crate::conn::io::{Net, SystemNet};
use crate::cookie::Jar;

/// A share, cloned to give it to another handle.
#[derive(Clone)]
pub struct Share(TryRc<Inner>);

struct Inner {
    /// `None` while a multi has them.
    caches: RefCell<Option<Caches>>,
    cookies: RefCell<Cookies>,
    /// What the connections left idle at the end are closed through, as
    /// C's share closes them through its own internal handle.
    net: RefCell<Box<dyn Net>>,
}

/// The share's caches are lent to a perform under way.
#[derive(Debug)]
pub struct Lent;

impl Share {
    /// A share whose connections are the system's.
    pub fn new() -> Result<Share, OutOfMemory> {
        Share::with_net(try_box(SystemNet)?)
    }

    /// A share whose connections are `net`'s.
    pub fn with_net(net: Box<dyn Net>) -> Result<Share, OutOfMemory> {
        Ok(Share(TryRc::try_new(Inner {
            caches: RefCell::new(Some(Caches::new()?)),
            cookies: RefCell::new(Cookies::NotKept),
            net: RefCell::new(net),
        })?))
    }

    /// The caches, for a multi to use until it gives them back.
    pub(crate) fn lend(&self) -> Result<Caches, Lent> {
        self.0.caches.borrow_mut().take().ok_or(Lent)
    }

    /// The caches lent, back, with nothing leased.
    pub(crate) fn give_back(&self, caches: Caches) {
        #[cfg(debug_assertions)]
        assert_eq!(caches.pool.leased(), 0, "a connection lent out with them");
        let mut slot = self.0.caches.borrow_mut();
        assert!(slot.is_none(), "given back twice");
        *slot = Some(caches);
    }
}

/// The share's cookie jar.
enum Cookies {
    NotKept,
    Here(Jar),
    /// A transfer's handle has it.
    Lent,
}

impl Share {
    /// Keep the cookies of the transfers given the share, in one jar for
    /// them all, from now on: each transfer whose own options turn its
    /// jar on uses the share's in its place.
    pub fn keep_cookies(&self) {
        let mut cookies = self.0.cookies.borrow_mut();
        if matches!(*cookies, Cookies::NotKept) {
            *cookies = Cookies::Here(Jar::default());
        }
    }

    /// Keep no cookies from now on, forgetting those kept
    /// (`CURLSHOPT_UNSHARE` of `CURL_LOCK_DATA_COOKIE`).
    pub fn forget_cookies(&self) -> Result<(), Lent> {
        let mut cookies = self.0.cookies.borrow_mut();
        if matches!(*cookies, Cookies::Lent) {
            return Err(Lent);
        }
        *cookies = Cookies::NotKept;
        Ok(())
    }

    /// How many hold the share: its clones, this one among them.
    pub fn holders(&self) -> usize {
        TryRc::count(&self.0)
    }

    /// The jar, if the share keeps one, for a handle to use until it gives
    /// it back.
    pub(crate) fn lend_cookies(&self) -> Result<Option<Jar>, Lent> {
        let mut cookies = self.0.cookies.borrow_mut();
        match std::mem::replace(&mut *cookies, Cookies::Lent) {
            Cookies::NotKept => {
                *cookies = Cookies::NotKept;
                Ok(None)
            }
            Cookies::Here(jar) => Ok(Some(jar)),
            Cookies::Lent => Err(Lent),
        }
    }

    /// The jar lent, back.
    pub(crate) fn give_back_cookies(&self, jar: Jar) {
        let mut cookies = self.0.cookies.borrow_mut();
        assert!(matches!(*cookies, Cookies::Lent), "a jar given back unlent");
        *cookies = Cookies::Here(jar);
    }
}

impl fmt::Debug for Share {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Share")
    }
}

impl Drop for Inner {
    /// The share's idle connections close with it (`curl_share_cleanup`).
    fn drop(&mut self) {
        let caches = self.caches.get_mut().as_mut().expect("given back");
        caches.pool.close_idle(&mut **self.net.get_mut());
    }
}

// What a share holds may move to whichever thread uses it next.
const _: () = {
    const fn sendable<T: Send>() {}
    sendable::<Caches>();
    sendable::<Jar>();
};
