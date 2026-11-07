//! mbedTLS for the curl rewrite: the system's library, as the C build
//! links it, 3.2 or later and before 4.0.
//!
//! TLS (`lib/vtls/mbedtls.c`), behind `curl_core::tls::TlsBackend`. What
//! the session does is safe code (`session.rs`, `verify.rs`,
//! `suites.rs`) over the library's calls (`library.rs`), which
//! `mbedtls.rs` makes; the tests drive it through a scripted library of
//! their own.
//!
//! C keeps the random number generator its sessions and keys draw on in a
//! file-scope static, made by the global init (`mbedtls_init`); here it
//! is the `MbedTls` value's, made by its `init`, and each session holds
//! it as long as it lives.

#![cfg_attr(test, allow(clippy::disallowed_methods, clippy::disallowed_macros))]

mod library;
mod mbedtls;
mod session;
mod suites;
mod sys;
mod verify;

#[cfg(test)]
mod fake;
#[cfg(test)]
mod tests;

use core::fmt;
use std::sync::Mutex;

use curl_alloc::{OutOfMemory, TryArc, try_box};
use curl_core::error::ErrorKind;
use curl_core::tls::{
    Alpn, CaDefaults, SystemStore, TlsBackend, TlsIdentity, TlsPeer, TlsSession, TlsShared,
    TlsSupport,
};

/// The CA bundle and path the build found (`build.rs`).
mod ca {
    include!(concat!(env!("OUT_DIR"), "/ca.rs"));
}

/// mbedTLS, as the core's TLS library: the library's random number
/// generator once `init` has made it, which every session draws on.
#[derive(Debug)]
pub struct MbedTls {
    rng: Mutex<Option<TryArc<mbedtls::Rng>>>,
}

impl MbedTls {
    /// The library, not yet initialised: it makes no session until
    /// `init` succeeds.
    pub const fn new() -> MbedTls {
        MbedTls {
            rng: Mutex::new(None),
        }
    }

    /// Initialise the library, as C's global init does (`mbedtls_init`):
    /// its PSA crypto, and the random number generator, seeded from the
    /// system's entropy with prediction resistance on. Whether it could.
    /// Each successful call is matched by `cleanup`'s.
    pub fn init(&self) -> bool {
        if !mbedtls::init() {
            return false;
        }
        // The generator is the library's, a static C's memory debugging
        // never sees: the debug build's tracker does not count it either.
        let make = || {
            let rng = library::Mbedtls::rng(&mbedtls::MBEDTLS).ok()?;
            TryArc::try_new(rng).ok()
        };
        #[cfg(feature = "debug-hooks")]
        let made = curl_alloc::track::untracked(make);
        #[cfg(not(feature = "debug-hooks"))]
        let made = make();
        let Some(rng) = made else {
            return false;
        };
        *self.rng.lock().expect("panics abort") = Some(rng);
        true
    }

    /// Let the library go, as C's global cleanup does
    /// (`mbedtls_cleanup`). A session still alive keeps the generator it
    /// draws on.
    pub fn cleanup(&self) {
        drop(self.rng.lock().expect("panics abort").take());
        mbedtls::deinit();
    }
}

impl Default for MbedTls {
    fn default() -> MbedTls {
        MbedTls::new()
    }
}

/// What C's mbedTLS build has (`Curl_ssl_mbedtls.supports`): a CA path
/// and blob, the chain reported, pinning, the context callback, TLS 1.3's
/// suites, HTTPS proxies, a cipher list and a revocation list. Not the
/// CA cache, curves, signature algorithms, an issuer, Encrypted Client
/// Hello, the stapled status (no `cert_status_request`) or engines.
pub(crate) const SUPPORT: TlsSupport = TlsSupport {
    ca_path: true,
    ca_blob: true,
    ca_cache: false,
    cert_info: true,
    pinned_key: true,
    context_handler: true,
    https_proxy: true,
    ciphers: true,
    tls13_ciphers: true,
    curves: false,
    signature_algorithms: false,
    crl_file: true,
    issuer_cert: false,
    issuer_cert_blob: false,
    ech: false,
    cert_status: false,
    engines: false,
};

/// The library's name and version, as `version` says it.
struct Id;

impl fmt::Display for Id {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", version())
    }
}

impl TlsBackend for MbedTls {
    fn id(&self) -> &dyn fmt::Display {
        &Id
    }

    fn session(
        &self,
        identity: &TryArc<TlsIdentity>,
        peer: &TlsPeer<'_>,
        alpn: Alpn,
        _shared: &TlsShared,
    ) -> Result<Box<dyn TlsSession>, ErrorKind> {
        // Not initialised, the library makes nothing, as C's global init
        // that failed leaves no TLS.
        let rng = self.rng.lock().expect("panics abort").clone();
        let Some(rng) = rng else {
            return Err(ErrorKind::FailedInit);
        };
        let session = session::Session::new(&mbedtls::MBEDTLS, rng, identity, peer, alpn)?;
        Ok(try_box(session).map_err(|OutOfMemory| ErrorKind::OutOfMemory)?)
    }

    /// The bundle and directory found at build. The system's store is
    /// never loaded: C's mbedTLS session reads no `native_ca_store`.
    fn ca_defaults(&self) -> CaDefaults {
        CaDefaults {
            file: ca::CA_BUNDLE,
            path: ca::CA_PATH,
            system: SystemStore::Asked,
        }
    }

    fn support(&self) -> TlsSupport {
        SUPPORT
    }
}

/// A library a handle names by reference: the shim's and the tool's own
/// `MbedTls`, which outlives every handle.
impl TlsBackend for &'static MbedTls {
    fn id(&self) -> &dyn fmt::Display {
        (**self).id()
    }

    fn session(
        &self,
        identity: &TryArc<TlsIdentity>,
        peer: &TlsPeer<'_>,
        alpn: Alpn,
        shared: &TlsShared,
    ) -> Result<Box<dyn TlsSession>, ErrorKind> {
        (**self).session(identity, peer, alpn, shared)
    }

    fn ca_defaults(&self) -> CaDefaults {
        (**self).ca_defaults()
    }

    fn support(&self) -> TlsSupport {
        (**self).support()
    }
}

/// The library's version, as the version string names it
/// (`mbedtls_version`): `mbedTLS/3.6.7`.
pub fn version() -> impl fmt::Display {
    struct Version;
    impl fmt::Display for Version {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            let v = mbedtls::version();
            write!(
                f,
                "mbedTLS/{}.{}.{}",
                v >> 24,
                (v >> 16) & 0xff,
                (v >> 8) & 0xff
            )
        }
    }
    Version
}
