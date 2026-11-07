//! The TLS library this build has, one of three chosen as it is built:
//! OpenSSL (the `openssl` feature), with HTTP/3 over ngtcp2 and Ed25519
//! for message signatures; GnuTLS (`gnutls`), with Ed25519 and no
//! HTTP/3; or Schannel (`schannel`, Windows only), with neither, as C's
//! builds with them have.

use core::fmt;

use curl_alloc::{OutOfMemory, try_box};
use curl_core::tls::{CaDefaults, SharedKeyLog, TlsBackend, TlsSupport};

#[cfg(any(
    all(feature = "openssl", feature = "schannel"),
    all(feature = "openssl", feature = "gnutls"),
    all(feature = "gnutls", feature = "schannel")
))]
compile_error!(
    "one TLS library: the `openssl`, `gnutls` and `schannel` features exclude each other"
);
#[cfg(not(any(feature = "openssl", feature = "gnutls", feature = "schannel")))]
compile_error!("a TLS library: the `openssl` feature, the `gnutls` one or the `schannel` one");

#[cfg(feature = "openssl")]
mod library {
    use super::*;

    /// The library, logging the secrets of its connections to `keylog`.
    pub(crate) fn tls(keylog: &SharedKeyLog) -> Result<Box<dyn TlsBackend>, OutOfMemory> {
        Ok(try_box(curl_openssl::OpenSsl::logging_keys_to(
            keylog.clone(),
        ))?)
    }

    pub(crate) const ED25519: Option<&'static dyn curl_core::libraries::Ed25519> =
        Some(&curl_openssl::ED25519);
    pub(crate) const H3: Option<&'static dyn curl_core::http3::Http3> = Some(&curl_ngtcp2::NGTCP2);

    /// Read its configuration, as C's global init does (`ossl_init`):
    /// whether it could.
    pub(crate) fn init() -> bool {
        curl_openssl::init();
        true
    }

    /// The key log is opened as the library is initialised (`ossl_init`).
    pub(crate) const KEYLOG_AT_INIT: bool = true;

    /// Its crypto engines' ids.
    pub(crate) fn engines() -> Result<Vec<Vec<u8>>, OutOfMemory> {
        curl_openssl::OPENSSL.engines()
    }

    /// Its version as the version string names it: `OpenSSL/3.5.9`.
    pub(crate) fn version() -> impl fmt::Display {
        curl_openssl::version()
    }

    /// The QUIC libraries, as the version string names them.
    pub(crate) fn quic() -> Option<impl fmt::Display> {
        Some(curl_ngtcp2::version())
    }

    /// What it can do past the handshake.
    pub(crate) fn support() -> TlsSupport {
        curl_openssl::OPENSSL.support()
    }

    /// What it trusts where a transfer names nothing.
    pub(crate) fn ca_defaults() -> CaDefaults {
        curl_openssl::OPENSSL.ca_defaults()
    }
}

#[cfg(feature = "gnutls")]
mod library {
    use super::*;

    /// The library, logging the secrets of its connections to `keylog`.
    pub(crate) fn tls(keylog: &SharedKeyLog) -> Result<Box<dyn TlsBackend>, OutOfMemory> {
        Ok(try_box(curl_gnutls::GnuTls::logging_keys_to(
            keylog.clone(),
        ))?)
    }

    pub(crate) const ED25519: Option<&'static dyn curl_core::libraries::Ed25519> =
        Some(&curl_gnutls::ED25519);
    pub(crate) const H3: Option<&'static dyn curl_core::http3::Http3> = None;

    /// The library initialised, as C's global init does (`gtls_init`):
    /// whether it could.
    pub(crate) fn init() -> bool {
        curl_gnutls::init()
    }

    /// The key log is opened by each session as it is made
    /// (`Curl_gtls_ctx_init`), not as the library is initialised.
    pub(crate) const KEYLOG_AT_INIT: bool = false;

    /// None: GnuTLS has no engines.
    pub(crate) fn engines() -> Result<Vec<Vec<u8>>, OutOfMemory> {
        curl_gnutls::GNUTLS.engines()
    }

    /// Its version as the version string names it: `GnuTLS/3.8.13`.
    pub(crate) fn version() -> impl fmt::Display {
        curl_gnutls::version()
    }

    /// None: no QUIC over GnuTLS.
    pub(crate) fn quic() -> Option<&'static str> {
        None
    }

    /// What it can do past the handshake.
    pub(crate) fn support() -> TlsSupport {
        curl_gnutls::GNUTLS.support()
    }

    /// What it trusts where a transfer names nothing.
    pub(crate) fn ca_defaults() -> CaDefaults {
        curl_gnutls::GNUTLS.ca_defaults()
    }
}

#[cfg(feature = "schannel")]
mod library {
    use super::*;

    /// Schannel, which logs no secrets.
    pub(crate) fn tls(keylog: &SharedKeyLog) -> Result<Box<dyn TlsBackend>, OutOfMemory> {
        let _ = keylog;
        Ok(try_box(curl_schannel::Schannel)?)
    }

    pub(crate) const ED25519: Option<&'static dyn curl_core::libraries::Ed25519> = None;
    pub(crate) const H3: Option<&'static dyn curl_core::http3::Http3> = None;

    /// Nothing: Schannel is the system's.
    pub(crate) fn init() -> bool {
        true
    }

    /// Schannel logs no keys; the log is opened as OpenSSL's is.
    pub(crate) const KEYLOG_AT_INIT: bool = true;

    /// None: Schannel has no engines.
    pub(crate) fn engines() -> Result<Vec<Vec<u8>>, OutOfMemory> {
        curl_schannel::SCHANNEL.engines()
    }

    /// `Schannel`, as C's `schannel_version` says it.
    pub(crate) fn version() -> impl fmt::Display {
        "Schannel"
    }

    /// None: no QUIC.
    pub(crate) fn quic() -> Option<&'static str> {
        None
    }

    /// What it can do past the handshake.
    pub(crate) fn support() -> TlsSupport {
        curl_schannel::SCHANNEL.support()
    }

    /// What it trusts where a transfer names nothing.
    pub(crate) fn ca_defaults() -> CaDefaults {
        curl_schannel::SCHANNEL.ca_defaults()
    }
}

pub(crate) use library::*;
