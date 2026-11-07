//! The certificates to trust that a multi keeps for its next connections,
//! so that they are not loaded again (C's `ossl_x509_share`,
//! `gtls_shared_creds`, `wssl_x509_share`, each kept in the multi's
//! `proto_hash`): one store of the library's, kept with the settings it
//! was loaded for and the time it was, which a later connection takes
//! while it is young enough by its own transfer's CA cache and the
//! library finds its settings the same. Which settings may take and keep
//! a store, and which make two the same, are each library's.

use curl_alloc::TryArc;

use crate::options::CaCache;
use crate::time::Instant;
use crate::tls::TlsIdentity;

/// A multi's kept store, of the library's type `S`, if it keeps one.
pub struct StoreCache<S> {
    kept: Option<Kept<S>>,
}

struct Kept<S> {
    /// The settings it was loaded for.
    identity: TryArc<TlsIdentity>,
    /// When it was loaded, on the multi's clock.
    made: Instant,
    store: S,
}

impl<S> Default for StoreCache<S> {
    fn default() -> Self {
        StoreCache { kept: None }
    }
}

impl<S> StoreCache<S> {
    /// The kept store, if it serves a connection with `identity` at
    /// `now`: it is not too old for the transfer's CA cache, and `same`
    /// says the settings it was loaded for (the first) serve `identity`'s
    /// (the second).
    pub fn get(
        &self,
        identity: &TlsIdentity,
        now: Instant,
        same: impl FnOnce(&TlsIdentity, &TlsIdentity) -> bool,
    ) -> Option<&S> {
        let kept = self.kept.as_ref()?;
        (!expired(kept.made, now, identity.options.ca_cache) && same(&kept.identity, identity))
            .then_some(&kept.store)
    }

    /// Keep `store`, loaded at `now` for `identity`, in place of any kept
    /// before.
    pub fn set(&mut self, identity: &TryArc<TlsIdentity>, now: Instant, store: S) {
        self.kept = Some(Kept {
            identity: identity.clone(),
            made: now,
            store,
        });
    }
}

/// A store loaded at `made` is too old at `now` for a transfer keeping
/// stores as `cache` says (`ossl_cached_x509_store_expired`,
/// `gtls_shared_creds_expired`, `wssl_cached_x509_store_expired`), in
/// milliseconds as C counts them. With the cache off, every store is.
fn expired(made: Instant, now: Instant, cache: CaCache) -> bool {
    match cache {
        CaCache::Forever => false,
        CaCache::For(age) => now.ms_since(made) >= crate::time::millis(age),
        CaCache::Off => true,
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use crate::options::{CaSetting, TlsOptions};

    use super::*;

    const DAY: Duration = Duration::from_secs(24 * 60 * 60);

    fn identity(set: impl FnOnce(&mut TlsIdentity)) -> TryArc<TlsIdentity> {
        let mut i = TlsIdentity {
            verify_peer: true,
            verify_host: true,
            options: TlsOptions::default(),
            ca_defaults: crate::tls::CaDefaults::NONE,
        };
        i.options.ca_file = CaSetting::Given(b"/ca.pem".to_vec());
        set(&mut i);
        TryArc::try_new(i).unwrap()
    }

    fn at(secs: u64) -> Instant {
        Instant::EPOCH.after(Duration::from_secs(secs))
    }

    fn kept(identity: &TryArc<TlsIdentity>) -> StoreCache<u32> {
        let mut c = StoreCache::default();
        c.set(identity, at(0), 7);
        c
    }

    fn any(_: &TlsIdentity, _: &TlsIdentity) -> bool {
        true
    }

    #[test]
    fn a_kept_store_serves_until_it_is_a_day_old() {
        let i = identity(|_| {});
        let c = kept(&i);
        assert_eq!(c.get(&i, at(0), any), Some(&7));
        assert_eq!(c.get(&i, at(DAY.as_secs() - 1), any), Some(&7));
        // A day old is too old (`>=`).
        assert_eq!(c.get(&i, at(DAY.as_secs()), any), None);
        assert_eq!(StoreCache::<u32>::default().get(&i, at(0), any), None);
    }

    #[test]
    fn the_age_is_the_asking_transfer_s() {
        let c = kept(&identity(|_| {}));
        let forever = identity(|i| i.options.ca_cache = CaCache::Forever);
        assert_eq!(c.get(&forever, at(400 * DAY.as_secs()), any), Some(&7));
        let minute = identity(|i| i.options.ca_cache = CaCache::For(Duration::from_secs(60)));
        assert_eq!(c.get(&minute, at(59), any), Some(&7));
        assert_eq!(c.get(&minute, at(60), any), None);
        let off = identity(|i| i.options.ca_cache = CaCache::Off);
        assert_eq!(c.get(&off, at(0), any), None);
    }

    #[test]
    fn the_library_says_which_settings_are_the_same() {
        let i = identity(|_| {});
        let c = kept(&i);
        let other = identity(|i| i.options.ca_file = CaSetting::Given(b"/other.pem".to_vec()));
        let mut asked = None;
        let got = c.get(&other, at(0), |k, w| {
            asked = Some((
                k.ca_file().map(<[u8]>::to_vec),
                w.ca_file().map(<[u8]>::to_vec),
            ));
            false
        });
        assert_eq!(got, None);
        assert_eq!(
            asked,
            Some((Some(b"/ca.pem".to_vec()), Some(b"/other.pem".to_vec()))),
            "the kept settings first, the asking second"
        );
    }

    #[test]
    fn the_last_store_set_is_kept() {
        let mut c = kept(&identity(|_| {}));
        let file = identity(|i| i.options.ca_file = CaSetting::Given(b"/other.pem".to_vec()));
        c.set(&file, at(5), 8);
        let same_file = |k: &TlsIdentity, w: &TlsIdentity| k.ca_file() == w.ca_file();
        assert_eq!(c.get(&file, at(5), same_file), Some(&8));
        assert_eq!(c.get(&identity(|_| {}), at(5), same_file), None);
    }
}
