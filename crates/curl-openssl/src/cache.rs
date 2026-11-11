//! The store of certificates to trust that a multi keeps for its next
//! connections, so that they are not loaded again (`ossl_x509_share`,
//! `ossl_get_cached_x509_store`, `ossl_set_cached_x509_store`): one store,
//! kept with the settings it was loaded for, which a later connection
//! takes while it is young enough and its settings name the same CA file,
//! CA path and partial-chain choice.

use curl_core::options::{CaCache, SslOptions};
use curl_core::tls::TlsIdentity;

/// What this library keeps for a multi: the store its connections last
/// loaded, of the library's type `S` (`curl_core::tls::StoreCache`).
pub(crate) type StoreCache<S> = curl_core::tls::StoreCache<S>;

/// A connection with `identity` may take a kept store and keep the one it
/// loads (`Curl_ssl_setup_x509_store`'s `cache_criteria_met`): the cache
/// is on, and the peer is verified against the CA file and path alone, no
/// blob, no revocation list and not the system's own store, asked for
/// or the library's default (`native_ca_store`). (C also
/// leaves a store loaded under an OpenSSL provider out; this build loads
/// none.)
pub(crate) fn cacheable(identity: &TlsIdentity) -> bool {
    let o = &identity.options;
    o.ca_cache != CaCache::Off
        && identity.verify_peer
        && identity.ca_blob().is_none()
        && o.crl_file.is_none()
        && !identity.native_ca_store()
}

/// A store loaded for `kept` serves `wanted`
/// (`ossl_cached_x509_store_different`).
pub(crate) fn same(kept: &TlsIdentity, wanted: &TlsIdentity) -> bool {
    let partial = |i: &TlsIdentity| i.options.ssl_options.contains(SslOptions::NO_PARTIALCHAIN);
    partial(kept) == partial(wanted)
        && kept.ca_file() == wanted.ca_file()
        && kept.ca_path() == wanted.ca_path()
}

#[cfg(test)]
mod tests {
    use curl_alloc::TryArc;
    use curl_core::options::{CaSetting, TlsOptions};

    use super::*;

    fn identity(set: impl FnOnce(&mut TlsIdentity)) -> TryArc<TlsIdentity> {
        let mut i = TlsIdentity {
            verify_peer: true,
            verify_host: true,
            options: TlsOptions::default(),
            ca_defaults: curl_core::tls::CaDefaults::NONE,
            origin: curl_core::tls::TlsOrigin::First,
        };
        i.options.ca_file = CaSetting::Given(b"/ca.pem".to_vec());
        set(&mut i);
        TryArc::try_new(i).unwrap()
    }

    #[test]
    fn another_ca_file_path_or_partial_chain_bit_is_another_store() {
        let base = identity(|_| {});
        assert!(same(&base, &identity(|_| {})));
        let file = identity(|i| i.options.ca_file = CaSetting::Given(b"/other.pem".to_vec()));
        assert!(!same(&base, &file));
        let path = identity(|i| i.options.ca_path = CaSetting::Given(b"/certs".to_vec()));
        assert!(!same(&base, &path));
        let partial = identity(|i| i.options.ssl_options = SslOptions::NO_PARTIALCHAIN);
        assert!(!same(&base, &partial));
        assert!(!same(&partial, &base));
        // What the settings resolve to is compared: the default named
        // is the default kept.
        let defaults = curl_core::tls::CaDefaults {
            file: Some("/ca.pem"),
            path: None,
            system: curl_core::tls::SystemStore::Asked,
        };
        let named = identity(|i| i.ca_defaults = defaults);
        let default = identity(|i| {
            i.ca_defaults = defaults;
            i.options.ca_file = CaSetting::Default;
        });
        assert!(same(&named, &default));
        // Settings outside the key do not matter.
        let other = identity(|i| i.options.ciphers = Some(b"AES".to_vec()));
        assert!(same(&base, &other));
    }

    #[test]
    fn only_a_verified_peer_by_file_and_path_alone_is_cached() {
        assert!(cacheable(&identity(|_| {})));
        assert!(!cacheable(&identity(|i| i.verify_peer = false)));
        assert!(!cacheable(&identity(|i| i.options.ca_cache = CaCache::Off)));
        assert!(!cacheable(&identity(
            |i| i.options.ca_blob = CaSetting::Given(b"PEM".to_vec())
        )));
        assert!(!cacheable(&identity(
            |i| i.options.crl_file = Some(b"/crl".to_vec())
        )));
        assert!(!cacheable(&identity(
            |i| i.options.ssl_options = SslOptions::NATIVE_CA
        )));
        // Nor where the library makes the system's store the default and
        // nothing is named.
        let native = |file| {
            identity(move |i| {
                i.ca_defaults.system = curl_core::tls::SystemStore::Default;
                i.options.ca_file = file;
            })
        };
        assert!(!cacheable(&native(CaSetting::Default)));
        assert!(cacheable(&native(CaSetting::Given(b"/ca.pem".to_vec()))));
        // Not verifying the host still caches.
        assert!(cacheable(&identity(|i| i.verify_host = false)));
    }
}
