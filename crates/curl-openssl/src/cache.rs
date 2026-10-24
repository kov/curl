//! The store of certificates to trust that a multi keeps for its next
//! connections, so that they are not loaded again (`ossl_x509_share`,
//! `ossl_get_cached_x509_store`, `ossl_set_cached_x509_store`): one store,
//! kept with the settings it was loaded for, which a later connection
//! takes while it is young enough and its settings name the same CA file,
//! CA path and partial-chain choice.

use curl_alloc::TryArc;
use curl_core::options::{CaCache, SslOptions};
use curl_core::time::Instant;
use curl_core::tls::TlsIdentity;

/// A multi's kept store, of the library's type `S`.
pub(crate) struct StoreCache<S> {
    kept: Option<Kept<S>>,
}

struct Kept<S> {
    /// The settings it was loaded for: the CA file and path they resolve
    /// to, and the partial-chain bit, are what a connection must share.
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

/// A connection with `identity` may take a kept store and keep the one it
/// loads (`Curl_ssl_setup_x509_store`'s `cache_criteria_met`): the cache
/// is on, and the peer is verified against the CA file and path alone, no
/// blob, no revocation list and not the system's own store. (C also
/// leaves a store loaded under an OpenSSL provider out; this build loads
/// none.)
pub(crate) fn cacheable(identity: &TlsIdentity) -> bool {
    let o = &identity.options;
    o.ca_cache != CaCache::Off
        && identity.verify_peer
        && o.ca_blob.is_none()
        && o.crl_file.is_none()
        && !o.ssl_options.contains(SslOptions::NATIVE_CA)
}

/// A store loaded for `kept` serves `wanted`
/// (`ossl_cached_x509_store_different`).
fn same(kept: &TlsIdentity, wanted: &TlsIdentity) -> bool {
    let partial = |i: &TlsIdentity| i.options.ssl_options.contains(SslOptions::NO_PARTIALCHAIN);
    partial(kept) == partial(wanted)
        && kept.ca_file() == wanted.ca_file()
        && kept.ca_path() == wanted.ca_path()
}

/// A store loaded at `made` is too old at `now` for a transfer keeping
/// stores as `cache` says (`ossl_cached_x509_store_expired`).
fn expired(made: Instant, now: Instant, cache: CaCache) -> bool {
    match cache {
        CaCache::Forever => false,
        CaCache::For(age) => now.since(made) >= age,
        // Not asked: nothing is taken without the cache on.
        CaCache::Off => true,
    }
}

impl<S> StoreCache<S> {
    /// The kept store, if it serves a connection with `identity` at
    /// `now`.
    pub(crate) fn get(&self, identity: &TlsIdentity, now: Instant) -> Option<&S> {
        let kept = self.kept.as_ref()?;
        (!expired(kept.made, now, identity.options.ca_cache) && same(&kept.identity, identity))
            .then_some(&kept.store)
    }

    /// Keep `store`, loaded at `now` for `identity`, in place of any kept
    /// before.
    pub(crate) fn set(&mut self, identity: &TryArc<TlsIdentity>, now: Instant, store: S) {
        self.kept = Some(Kept {
            identity: identity.clone(),
            made: now,
            store,
        });
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use curl_core::options::{CaSetting, TlsOptions};

    use super::*;

    const DAY: Duration = Duration::from_secs(24 * 60 * 60);

    fn identity(set: impl FnOnce(&mut TlsIdentity)) -> TryArc<TlsIdentity> {
        let mut i = TlsIdentity {
            verify_peer: true,
            verify_host: true,
            options: TlsOptions::default(),
            ca_defaults: Default::default(),
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

    #[test]
    fn a_kept_store_serves_the_same_settings_until_it_is_a_day_old() {
        let i = identity(|_| {});
        let c = kept(&i);
        assert_eq!(c.get(&i, at(0)), Some(&7));
        assert_eq!(c.get(&identity(|_| {}), at(DAY.as_secs() - 1)), Some(&7));
        // A day old is too old (`>=`).
        assert_eq!(c.get(&i, at(DAY.as_secs())), None);
        assert_eq!(StoreCache::<u32>::default().get(&i, at(0)), None);
    }

    #[test]
    fn the_age_is_the_asking_transfer_s() {
        let c = kept(&identity(|_| {}));
        let forever = identity(|i| i.options.ca_cache = CaCache::Forever);
        assert_eq!(c.get(&forever, at(400 * DAY.as_secs())), Some(&7));
        let minute = identity(|i| i.options.ca_cache = CaCache::For(Duration::from_secs(60)));
        assert_eq!(c.get(&minute, at(59)), Some(&7));
        assert_eq!(c.get(&minute, at(60)), None);
    }

    #[test]
    fn another_ca_file_path_or_partial_chain_bit_is_another_store() {
        let c = kept(&identity(|_| {}));
        let file = identity(|i| i.options.ca_file = CaSetting::Given(b"/other.pem".to_vec()));
        assert_eq!(c.get(&file, at(0)), None);
        let path = identity(|i| i.options.ca_path = CaSetting::Given(b"/certs".to_vec()));
        assert_eq!(c.get(&path, at(0)), None);
        let partial = identity(|i| i.options.ssl_options = SslOptions::NO_PARTIALCHAIN);
        assert_eq!(c.get(&partial, at(0)), None);
        // What the settings resolve to is compared: the default named
        // is the default kept.
        let defaults = curl_core::tls::CaDefaults {
            file: Some("/ca.pem"),
            path: None,
        };
        let named = identity(|i| i.ca_defaults = defaults);
        let default = identity(|i| {
            i.ca_defaults = defaults;
            i.options.ca_file = CaSetting::Default;
        });
        assert_eq!(kept(&named).get(&default, at(0)), Some(&7));
        // Settings outside the key do not matter.
        let other = identity(|i| i.options.ciphers = Some(b"AES".to_vec()));
        assert_eq!(c.get(&other, at(0)), Some(&7));
    }

    #[test]
    fn the_last_store_set_is_kept() {
        let mut c = kept(&identity(|_| {}));
        let file = identity(|i| i.options.ca_file = CaSetting::Given(b"/other.pem".to_vec()));
        c.set(&file, at(5), 8);
        assert_eq!(c.get(&file, at(5)), Some(&8));
        assert_eq!(c.get(&identity(|_| {}), at(5)), None);
    }

    #[test]
    fn only_a_verified_peer_by_file_and_path_alone_is_cached() {
        assert!(cacheable(&identity(|_| {})));
        assert!(!cacheable(&identity(|i| i.verify_peer = false)));
        assert!(!cacheable(&identity(|i| i.options.ca_cache = CaCache::Off)));
        assert!(!cacheable(&identity(
            |i| i.options.ca_blob = Some(b"PEM".to_vec())
        )));
        assert!(!cacheable(&identity(
            |i| i.options.crl_file = Some(b"/crl".to_vec())
        )));
        assert!(!cacheable(&identity(
            |i| i.options.ssl_options = SslOptions::NATIVE_CA
        )));
        // Not verifying the host still caches.
        assert!(cacheable(&identity(|i| i.verify_host = false)));
    }
}
