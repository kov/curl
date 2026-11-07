//! GnuTLS for the curl rewrite: the system's library, as the C build
//! links it, 3.6.5 or later.
//!
//! TLS (`lib/vtls/gtls.c`), behind `curl_core::tls::TlsBackend`, and
//! Ed25519 for HTTP message signatures with its nettle
//! (`lib/curl_ed25519.c`), behind `curl_core::libraries::Ed25519`. What
//! the session does is safe code (`session.rs`, `trust.rs`, `verify.rs`)
//! over the library's calls (`library.rs`), which `gnutls.rs` makes; the
//! tests drive it through a scripted library of their own.

#![cfg_attr(test, allow(clippy::disallowed_methods, clippy::disallowed_macros))]

mod gnutls;
mod library;
mod priority;
mod session;
mod sign;
mod sys;
mod trust;
mod verify;

#[cfg(test)]
mod fake;
#[cfg(test)]
mod tests;

use core::fmt;

use curl_alloc::{OutOfMemory, TryArc, try_box};
use curl_core::error::ErrorKind;
use curl_core::tls::{
    Alpn, CaDefaults, SharedKeyLog, SystemStore, TlsBackend, TlsIdentity, TlsPeer, TlsSession,
    TlsShared, TlsSupport,
};

pub use sign::ED25519;

/// The CA bundle and path the build found (`build.rs`).
mod ca {
    include!(concat!(env!("OUT_DIR"), "/ca.rs"));
}

/// GnuTLS, as the core's TLS library, logging the secrets of its
/// connections to a key log if it is given one. Each session it makes
/// holds the key log too, so it lasts as long as the session.
#[derive(Debug)]
pub struct GnuTls {
    keylog: Option<SharedKeyLog>,
}

/// GnuTLS, logging no secrets.
pub static GNUTLS: GnuTls = GnuTls { keylog: None };

impl GnuTls {
    /// GnuTLS logging the secrets of its connections to `keylog`
    /// (`SSLKEYLOGFILE`) while it is open.
    pub const fn logging_keys_to(keylog: SharedKeyLog) -> GnuTls {
        GnuTls {
            keylog: Some(keylog),
        }
    }
}

/// What C's GnuTLS build has (`Curl_ssl_gnutls.supports`): a CA path and
/// blob, their cache, the chain reported, pinning, HTTPS proxies, a
/// cipher list (a priority string), a revocation list and an issuer from
/// a file; the stapled status (`gtls_cert_status_request`). Not an
/// issuer blob, the context callback, TLS 1.3's suites, curves or
/// signature algorithms, Encrypted Client Hello or engines.
pub(crate) const SUPPORT: TlsSupport = TlsSupport {
    ca_path: true,
    ca_blob: true,
    ca_cache: true,
    cert_info: true,
    pinned_key: true,
    context_handler: false,
    https_proxy: true,
    ciphers: true,
    tls13_ciphers: false,
    curves: false,
    signature_algorithms: false,
    crl_file: true,
    issuer_cert: true,
    issuer_cert_blob: false,
    ech: false,
    cert_status: true,
    engines: false,
};

/// The library's name and version, as `version` says it.
struct Id;

impl fmt::Display for Id {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", version())
    }
}

impl TlsBackend for GnuTls {
    fn id(&self) -> &dyn fmt::Display {
        &Id
    }

    fn session(
        &self,
        identity: &TryArc<TlsIdentity>,
        peer: &TlsPeer<'_>,
        alpn: Alpn,
        shared: &TlsShared,
    ) -> Result<Box<dyn TlsSession>, ErrorKind> {
        let session = session::Session::new(
            &gnutls::GNUTLS,
            identity,
            peer,
            alpn,
            shared,
            self.keylog.clone(),
        )?;
        Ok(try_box(session).map_err(|OutOfMemory| ErrorKind::OutOfMemory)?)
    }

    /// The bundle and directory found at build; the system's store only
    /// where asked (`CURLSSLOPT_NATIVE_CA`), but as the build's default
    /// where it is C's `CURL_CA_NATIVE` (the `native-ca` feature).
    fn ca_defaults(&self) -> CaDefaults {
        CaDefaults {
            file: ca::CA_BUNDLE,
            path: ca::CA_PATH,
            system: if cfg!(feature = "native-ca") {
                SystemStore::Default
            } else {
                SystemStore::Asked
            },
        }
    }

    fn support(&self) -> TlsSupport {
        SUPPORT
    }
}

/// The library's version, as the version string names it
/// (`Curl_gtls_version`): `GnuTLS/3.8.13`.
pub fn version() -> impl fmt::Display {
    struct Version;
    impl fmt::Display for Version {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(f, "GnuTLS/{}", curl_core::tls::Text(gnutls::version()))
        }
    }
    Version
}

/// Initialise the library, as C's global init does (`gtls_init`):
/// whether it could. Each successful call is matched by `cleanup`'s.
pub fn init() -> bool {
    gnutls::init()
}

/// Let the library go, as C's global cleanup does (`gtls_cleanup`).
pub fn cleanup() {
    gnutls::deinit();
}
