//! The share: connections and resolved names kept for every transfer
//! given it, whichever handle runs them (`CURLSH`, with
//! `CURL_LOCK_DATA_CONNECT` and `CURL_LOCK_DATA_DNS`).
//!
//! A transfer's multi borrows the caches whole for the length of a
//! perform, and gives them back at its end: one owner at a time, so no
//! lock guards them. A perform on a share already lent is refused.

use std::cell::RefCell;
use std::fmt;

use curl_alloc::{OutOfMemory, TryRc, try_box};

use crate::conn::Caches;
use crate::conn::io::{Net, SystemNet};

/// A share, cloned to give it to another handle.
#[derive(Clone)]
pub struct Share(TryRc<Inner>);

struct Inner {
    /// `None` while a multi has them.
    caches: RefCell<Option<Caches>>,
    /// What the connections left idle at the end are closed through, as
    /// C's share closes them through its own internal handle.
    net: RefCell<Box<dyn Net>>,
}

/// The share's caches are lent to a perform under way.
#[derive(Debug)]
pub(crate) struct Lent;

impl Share {
    /// A share whose connections are the system's.
    pub fn new() -> Result<Share, OutOfMemory> {
        Share::with_net(try_box(SystemNet)?)
    }

    /// A share whose connections are `net`'s.
    pub fn with_net(net: Box<dyn Net>) -> Result<Share, OutOfMemory> {
        Ok(Share(TryRc::try_new(Inner {
            caches: RefCell::new(Some(Caches::new()?)),
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
