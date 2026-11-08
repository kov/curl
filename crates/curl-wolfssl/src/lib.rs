//! wolfSSL for the curl rewrite: the library built as curl's CI builds it
//! (`inventory/measure/deps.py`), 5.0 or later.
//!
//! TLS (`lib/vtls/wolfssl.c`), behind `curl_core::tls::TlsBackend`, for
//! streams and for QUIC (`lib/vquic/vquic-tls.c`), and Ed25519 for HTTP
//! message signatures with wolfCrypt (`lib/curl_ed25519.c`), behind
//! `curl_core::libraries::Ed25519`. What the session does is safe code
//! (`session.rs`, `quic.rs`, `trust.rs`) over the library's calls
//! (`library.rs`), which `wolfssl.rs` makes; the tests drive it through a
//! scripted library of their own.
//!
//! C keeps the BIO method its sessions read and write through in a
//! file-scope static, made by the global init (`wssl_init`); here it is
//! the `WolfSsl` value's, made by its `init`, and each session's object
//! holds it as long as it lives.

#![cfg_attr(test, allow(clippy::disallowed_methods, clippy::disallowed_macros))]

mod library;
mod quic;
mod session;
mod sign;
mod sys;
mod trust;
mod wolfssl;

#[cfg(test)]
mod fake;
#[cfg(test)]
mod tests;

use core::fmt;
use curl_alloc::Lock;

use curl_alloc::{OutOfMemory, TryArc, try_box};
use curl_core::error::ErrorKind;
use curl_core::tls::{
    Alpn, CaDefaults, QuicContextSetup, QuicTls, SharedKeyLog, SystemStore, Text, TlsBackend,
    TlsCx, TlsIdentity, TlsPeer, TlsSession, TlsShared, TlsSupport,
};

pub use sign::ED25519;

/// The CA bundle and path the build found (`build.rs`).
mod ca {
    include!(concat!(env!("OUT_DIR"), "/ca.rs"));
}

/// wolfSSL, as the core's TLS library: the BIO method its sessions read
/// and write through once `init` has made it, and the key log its
/// sessions' secrets go to, if it is given one.
#[derive(Debug)]
pub struct WolfSsl {
    method: Lock<Option<TryArc<wolfssl::Method>>>,
    keylog: Option<SharedKeyLog>,
}

impl WolfSsl {
    /// The library, not yet initialised, logging no secrets: it makes no
    /// session until `init` succeeds.
    pub const fn new() -> WolfSsl {
        WolfSsl {
            method: Lock::new(None),
            keylog: None,
        }
    }

    /// The library logging the secrets of its connections to `keylog`
    /// (`SSLKEYLOGFILE`) while it is open, which the caller opens as C's
    /// global init does.
    pub const fn logging_keys_to(keylog: SharedKeyLog) -> WolfSsl {
        WolfSsl {
            method: Lock::new(None),
            keylog: Some(keylog),
        }
    }

    /// The library as `self` initialised it, logging the secrets of its
    /// connections to `keylog`: for the tool, whose key log is made after
    /// the library is initialised.
    pub fn with_keylog(&self, keylog: SharedKeyLog) -> WolfSsl {
        WolfSsl {
            method: Lock::new(self.method.lock().expect("panics abort").clone()),
            keylog: Some(keylog),
        }
    }

    /// Initialise the library, as C's global init does (`wssl_init`): the
    /// library, then the BIO method. Whether it could. Each successful
    /// call is matched by `cleanup`'s.
    pub fn init(&self) -> bool {
        if !wolfssl::init() {
            return false;
        }
        // The method is the library's, a static C's memory debugging
        // never sees: the debug build's tracker does not count it either.
        let make = || TryArc::try_new(wolfssl::Method::new()?).ok();
        #[cfg(feature = "debug-hooks")]
        let made = curl_alloc::track::untracked(make);
        #[cfg(not(feature = "debug-hooks"))]
        let made = make();
        let Some(method) = made else {
            return false;
        };
        *self.method.lock().expect("panics abort") = Some(method);
        true
    }

    /// Let the library go, as C's global cleanup does (`wssl_cleanup`):
    /// the method, then the library. A session still alive keeps the
    /// method it reads and writes through.
    pub fn cleanup(&self) {
        drop(self.method.lock().expect("panics abort").take());
        wolfssl::cleanup();
    }
}

impl Default for WolfSsl {
    fn default() -> WolfSsl {
        WolfSsl::new()
    }
}

/// What C's wolfSSL build has (`Curl_ssl_wolfssl.supports`): pinning
/// (`KEEP_PEER_CERT`), HTTPS proxies (the BIO chain), a CA path and blob,
/// the context callback, TLS 1.3's suites, the CA cache, a cipher list,
/// curves and Encrypted Client Hello (`HAVE_ECH`, which the build of the
/// library is checked for). Not the chain reported, a revocation list, an
/// issuer, signature algorithms, the stapled status (no
/// `cert_status_request`) or engines.
pub(crate) const SUPPORT: TlsSupport = TlsSupport {
    ca_path: true,
    ca_blob: true,
    ca_cache: true,
    cert_info: false,
    pinned_key: true,
    context_handler: true,
    https_proxy: true,
    ciphers: true,
    tls13_ciphers: true,
    curves: true,
    signature_algorithms: false,
    crl_file: false,
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

impl TlsBackend for WolfSsl {
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
        // Not initialised, the library makes nothing, as C's global init
        // that failed leaves no TLS.
        let method = self.method.lock().expect("panics abort").clone();
        let Some(method) = method else {
            return Err(ErrorKind::FailedInit);
        };
        let session = session::Session::new(
            &wolfssl::WOLFSSL,
            method,
            identity,
            peer,
            alpn,
            shared,
            self.keylog.clone(),
        )?;
        Ok(try_box(session).map_err(|OutOfMemory| ErrorKind::OutOfMemory)?)
    }

    /// A QUIC connection's session, its context and session's object
    /// made at once (`Curl_wssl_ctx_init` with QUIC's transport), the
    /// context handed to `setup` where C calls it.
    fn quic_session(
        &self,
        identity: &TryArc<TlsIdentity>,
        peer: &TlsPeer<'_>,
        shared: &TlsShared,
        setup: QuicContextSetup<'_>,
        cx: &mut TlsCx<'_>,
    ) -> Result<Box<dyn QuicTls>, ErrorKind> {
        let method = self.method.lock().expect("panics abort").clone();
        let Some(method) = method else {
            return Err(ErrorKind::FailedInit);
        };
        let session = session::Session::new_quic(
            &wolfssl::WOLFSSL,
            method,
            identity,
            peer,
            shared,
            self.keylog.clone(),
        )?;
        let session = quic::QuicSession::new(session, setup, cx)?;
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

/// A library a handle names by reference: the shim's and the tool's own
/// `WolfSsl`, which outlives every handle.
impl TlsBackend for &'static WolfSsl {
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

    fn quic_session(
        &self,
        identity: &TryArc<TlsIdentity>,
        peer: &TlsPeer<'_>,
        shared: &TlsShared,
        setup: QuicContextSetup<'_>,
        cx: &mut TlsCx<'_>,
    ) -> Result<Box<dyn QuicTls>, ErrorKind> {
        (**self).quic_session(identity, peer, shared, setup, cx)
    }

    fn ca_defaults(&self) -> CaDefaults {
        (**self).ca_defaults()
    }

    fn support(&self) -> TlsSupport {
        (**self).support()
    }
}

/// The library's version, as the version string names it
/// (`Curl_wssl_version`): `wolfSSL/5.9.4`.
pub fn version() -> impl fmt::Display {
    struct Version;
    impl fmt::Display for Version {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(f, "wolfSSL/{}", Text(wolfssl::version()))
        }
    }
    Version
}
