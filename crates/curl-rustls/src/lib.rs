//! Rustls for the curl rewrite: TLS as `lib/vtls/rustls.c` drives it over
//! rustls-ffi, behind `curl_core::tls::TlsBackend`, made of the rustls
//! crate itself at the version and with the crypto provider the rustls-ffi
//! release C is measured with builds it (0.15.5: rustls 0.23.46 over
//! aws-lc-rs). What the session does is safe code (`session.rs`) over the
//! calls C makes of rustls-ffi (`library.rs`), which `rustls.rs` makes of
//! rustls as rustls-ffi makes them, its failures said in rustls-ffi's
//! words (`result.rs`); the tests drive it through a scripted library of
//! their own, and the calls themselves against a rustls server.
//!
//! The crate is safe Rust throughout: it has no module allowed unsafe
//! code.

#![cfg_attr(test, allow(clippy::disallowed_methods, clippy::disallowed_macros))]

mod files;
mod library;
mod result;
mod rustls;
mod session;

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

/// The CA bundle and path the build found (`build.rs`).
mod ca {
    include!(concat!(env!("OUT_DIR"), "/ca.rs"));
}

/// The rustls-ffi release whose behaviour this crate has, and the rustls
/// it is built with, which this crate is too (`Cargo.toml`), as the
/// version string names them.
pub const RUSTLS_FFI_VERSION: &str = "0.15.5";
pub const RUSTLS_VERSION: &str = "0.23.46";

/// Rustls, as the core's TLS library, and the key log its sessions'
/// secrets go to, if it is given one. C's has no global state to set up
/// (its `init` is NULL); its cleanup closes the key log, which the shim's
/// root does here.
#[derive(Debug, Default)]
pub struct Rustls {
    keylog: Option<SharedKeyLog>,
}

impl Rustls {
    /// The library logging no secrets.
    pub const fn new() -> Rustls {
        Rustls { keylog: None }
    }

    /// The library logging the secrets of its connections to `keylog`
    /// (`SSLKEYLOGFILE`), which each connection opens as its configuration
    /// is built (`init_config_builder_keylog`).
    pub const fn logging_keys_to(keylog: SharedKeyLog) -> Rustls {
        Rustls {
            keylog: Some(keylog),
        }
    }
}

/// What C's Rustls build has (`Curl_ssl_rustls.supports`): a CA blob,
/// HTTPS proxies, a cipher list and TLS 1.3's suites, the chain reported
/// a revocation list and Encrypted Client Hello, whose HPKE the provider
/// here, aws-lc-rs's, always has. Not a CA path, the CA cache, pinning, the
/// context callback, curves, signature algorithms, an issuer, the
/// stapled status (no `cert_status_request`) or engines.
pub(crate) const SUPPORT: TlsSupport = TlsSupport {
    ca_path: false,
    ca_blob: true,
    ca_cache: false,
    cert_info: true,
    pinned_key: false,
    context_handler: false,
    https_proxy: true,
    ciphers: true,
    tls13_ciphers: true,
    curves: false,
    signature_algorithms: false,
    crl_file: true,
    issuer_cert: false,
    issuer_cert_blob: false,
    ech: true,
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

impl TlsBackend for Rustls {
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
        let session =
            session::Session::new(&rustls::RUSTLS, identity, peer, alpn, self.keylog.clone())?;
        Ok(try_box(session).map_err(|OutOfMemory| ErrorKind::OutOfMemory)?)
    }

    /// The bundle and directory found at build; the system's store only
    /// where asked for (`native_ca_store`), as C's build without
    /// `CURL_CA_NATIVE`.
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

/// A library a handle names by reference: the shim's own `Rustls`, which
/// outlives every handle.
impl TlsBackend for &'static Rustls {
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

/// The library's version, as the version string names it (`cr_version`,
/// `rustls_version`): `rustls-ffi/0.15.5/rustls/0.23.46/aws-lc-rs`. It
/// names rustls-ffi, which this build does not link, as C's does: the
/// test suites know a Rustls build by that name (`DIVERGENCE.md`).
pub fn version() -> impl fmt::Display {
    struct Version;
    impl fmt::Display for Version {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(
                f,
                "rustls-ffi/{RUSTLS_FFI_VERSION}/rustls/{RUSTLS_VERSION}/aws-lc-rs"
            )
        }
    }
    Version
}
