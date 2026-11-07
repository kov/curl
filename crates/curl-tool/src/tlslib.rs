//! The TLS library this build has, one of five chosen as it is built:
//! OpenSSL (the `openssl` feature), with HTTP/3 over ngtcp2 and Ed25519
//! for message signatures; GnuTLS (`gnutls`) or wolfSSL (`wolfssl`), with
//! HTTP/3 over ngtcp2 and Ed25519; or mbedTLS (`mbedtls`) or Schannel
//! (`schannel`, Windows only), with neither, as C's builds with them
//! have.

use core::fmt;

use curl_alloc::{OutOfMemory, try_box};
use curl_core::tls::{CaDefaults, SharedKeyLog, TlsBackend, TlsSupport};

#[cfg(any(
    all(feature = "openssl", feature = "gnutls"),
    all(feature = "openssl", feature = "mbedtls"),
    all(feature = "openssl", feature = "wolfssl"),
    all(feature = "openssl", feature = "schannel"),
    all(feature = "gnutls", feature = "mbedtls"),
    all(feature = "gnutls", feature = "wolfssl"),
    all(feature = "gnutls", feature = "schannel"),
    all(feature = "mbedtls", feature = "wolfssl"),
    all(feature = "mbedtls", feature = "schannel"),
    all(feature = "wolfssl", feature = "schannel")
))]
compile_error!(
    "one TLS library: the `openssl`, `gnutls`, `mbedtls`, `wolfssl` and `schannel` features \
     exclude each other"
);
#[cfg(not(any(
    feature = "openssl",
    feature = "gnutls",
    feature = "mbedtls",
    feature = "wolfssl",
    feature = "schannel"
)))]
compile_error!(
    "a TLS library: the `openssl`, `gnutls`, `mbedtls`, `wolfssl` or `schannel` feature"
);

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
    /// HTTP/3 over ngtcp2's GnuTLS crypto.
    pub(crate) const H3: Option<&'static dyn curl_core::http3::Http3> = Some(&curl_ngtcp2::NGTCP2);

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

    /// The QUIC libraries, as `quic_version` names them.
    pub(crate) fn quic() -> Option<impl fmt::Display> {
        Some(curl_ngtcp2::version())
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

#[cfg(feature = "mbedtls")]
mod library {
    use super::*;

    /// The tool's library, whose random number generator `init` makes.
    static MBEDTLS: curl_mbedtls::MbedTls = curl_mbedtls::MbedTls::new();

    /// mbedTLS, which logs no secrets.
    pub(crate) fn tls(keylog: &SharedKeyLog) -> Result<Box<dyn TlsBackend>, OutOfMemory> {
        let _no_keys: &SharedKeyLog = keylog;
        let tls: &'static curl_mbedtls::MbedTls = &MBEDTLS;
        Ok(try_box(tls)?)
    }

    pub(crate) const ED25519: Option<&'static dyn curl_core::libraries::Ed25519> = None;
    pub(crate) const H3: Option<&'static dyn curl_core::http3::Http3> = None;

    /// The library and its random number generator initialised, as C's
    /// global init does (`mbedtls_init`): whether it could.
    pub(crate) fn init() -> bool {
        MBEDTLS.init()
    }

    /// C's mbedTLS build never opens the key log: `SSLKEYLOGFILE` is not
    /// read.
    pub(crate) const KEYLOG_AT_INIT: bool = false;

    /// None: mbedTLS has no engines.
    pub(crate) fn engines() -> Result<Vec<Vec<u8>>, OutOfMemory> {
        MBEDTLS.engines()
    }

    /// Its version as the version string names it: `mbedTLS/3.6.7`.
    pub(crate) fn version() -> impl fmt::Display {
        curl_mbedtls::version()
    }

    /// None: no QUIC over mbedTLS.
    pub(crate) fn quic() -> Option<&'static str> {
        None
    }

    /// What it can do past the handshake.
    pub(crate) fn support() -> TlsSupport {
        MBEDTLS.support()
    }

    /// What it trusts where a transfer names nothing.
    pub(crate) fn ca_defaults() -> CaDefaults {
        MBEDTLS.ca_defaults()
    }
}

#[cfg(feature = "wolfssl")]
mod library {
    use super::*;

    /// The tool's library, whose BIO method `init` makes.
    static WOLFSSL: curl_wolfssl::WolfSsl = curl_wolfssl::WolfSsl::new();

    /// The library, logging the secrets of its connections to `keylog`.
    pub(crate) fn tls(keylog: &SharedKeyLog) -> Result<Box<dyn TlsBackend>, OutOfMemory> {
        Ok(try_box(WOLFSSL.with_keylog(keylog.clone()))?)
    }

    pub(crate) const ED25519: Option<&'static dyn curl_core::libraries::Ed25519> =
        Some(&curl_wolfssl::ED25519);
    /// HTTP/3 over ngtcp2's wolfSSL crypto.
    pub(crate) const H3: Option<&'static dyn curl_core::http3::Http3> = Some(&curl_ngtcp2::NGTCP2);

    /// The library and its BIO method initialised, as C's global init
    /// does (`wssl_init`): whether it could.
    pub(crate) fn init() -> bool {
        WOLFSSL.init()
    }

    /// The key log is opened as the library is initialised (`wssl_init`).
    pub(crate) const KEYLOG_AT_INIT: bool = true;

    /// None: wolfSSL has no engines.
    pub(crate) fn engines() -> Result<Vec<Vec<u8>>, OutOfMemory> {
        WOLFSSL.engines()
    }

    /// Its version as the version string names it: `wolfSSL/5.9.4`.
    pub(crate) fn version() -> impl fmt::Display {
        curl_wolfssl::version()
    }

    /// The QUIC libraries, as `quic_version` names them.
    pub(crate) fn quic() -> Option<impl fmt::Display> {
        Some(curl_ngtcp2::version())
    }

    /// What it can do past the handshake.
    pub(crate) fn support() -> TlsSupport {
        WOLFSSL.support()
    }

    /// What it trusts where a transfer names nothing.
    pub(crate) fn ca_defaults() -> CaDefaults {
        WOLFSSL.ca_defaults()
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
