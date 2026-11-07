//! The TLS library this build has, one of five chosen as it is built:
//! OpenSSL (the `openssl` feature), with HTTP/3 over ngtcp2 and Ed25519
//! for message signatures; GnuTLS (`gnutls`) or wolfSSL (`wolfssl`), with
//! Ed25519 and no HTTP/3; or mbedTLS (`mbedtls`) or Schannel (`schannel`,
//! Windows only), with neither, as C's builds with them have.

use core::ffi::CStr;
use core::fmt;

use crate::ffi;

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

    /// OpenSSL, logging secrets to the root's key log.
    pub(crate) static TLS: curl_openssl::OpenSsl = curl_openssl::OpenSsl::logging_keys_to(
        curl_core::tls::SharedKeyLog::of_static(&crate::root::KEYLOG),
    );

    pub(crate) const ED25519: Option<&'static dyn curl_core::libraries::Ed25519> =
        Some(&curl_openssl::ED25519);
    pub(crate) const H3: Option<&'static dyn curl_core::http3::Http3> = Some(&curl_ngtcp2::NGTCP2);

    /// Its id and name, as `curl_global_sslset` and
    /// `CURLINFO_TLS_SSL_PTR` give them.
    pub(crate) const ID: ffi::curl_sslbackend = ffi::CURLSSLBACKEND_OPENSSL;
    pub(crate) const NAME: &CStr = c"openssl";

    /// Read its configuration and open the key log, as C's global init
    /// does (`ossl_init`): whether it could.
    pub(crate) fn init() -> bool {
        curl_openssl::init();
        crate::root::KEYLOG.open();
        true
    }

    /// Nothing to let go of but the key log, which the root closes.
    pub(crate) fn cleanup() {}

    /// Its version as the version string names it: `OpenSSL/3.5.9`.
    pub(crate) fn version() -> impl fmt::Display {
        curl_openssl::version()
    }

    /// The QUIC libraries, as `quic_version` names them.
    pub(crate) fn quic() -> Option<impl fmt::Display> {
        Some(curl_ngtcp2::version())
    }
}

#[cfg(feature = "gnutls")]
mod library {
    use super::*;

    /// GnuTLS, logging secrets to the root's key log, which its sessions
    /// open as they are made (`Curl_gtls_ctx_init`).
    pub(crate) static TLS: curl_gnutls::GnuTls = curl_gnutls::GnuTls::logging_keys_to(
        curl_core::tls::SharedKeyLog::of_static(&crate::root::KEYLOG),
    );

    pub(crate) const ED25519: Option<&'static dyn curl_core::libraries::Ed25519> =
        Some(&curl_gnutls::ED25519);
    pub(crate) const H3: Option<&'static dyn curl_core::http3::Http3> = None;

    pub(crate) const ID: ffi::curl_sslbackend = ffi::CURLSSLBACKEND_GNUTLS;
    pub(crate) const NAME: &CStr = c"gnutls";

    /// The library initialised, as C's global init does (`gtls_init`):
    /// whether it could.
    pub(crate) fn init() -> bool {
        curl_gnutls::init()
    }

    /// The library let go, as C's last cleanup does (`gtls_cleanup`).
    pub(crate) fn cleanup() {
        curl_gnutls::cleanup();
    }

    /// Its version as the version string names it: `GnuTLS/3.8.13`.
    pub(crate) fn version() -> impl fmt::Display {
        curl_gnutls::version()
    }

    /// None: no QUIC over GnuTLS.
    pub(crate) fn quic() -> Option<&'static str> {
        None
    }
}

#[cfg(feature = "mbedtls")]
mod library {
    use super::*;

    /// mbedTLS, which logs no secrets (C's build never opens the log).
    pub(crate) static TLS: &curl_mbedtls::MbedTls = &MBEDTLS;
    static MBEDTLS: curl_mbedtls::MbedTls = curl_mbedtls::MbedTls::new();

    pub(crate) const ED25519: Option<&'static dyn curl_core::libraries::Ed25519> = None;
    pub(crate) const H3: Option<&'static dyn curl_core::http3::Http3> = None;

    pub(crate) const ID: ffi::curl_sslbackend = ffi::CURLSSLBACKEND_MBEDTLS;
    pub(crate) const NAME: &CStr = c"mbedtls";

    /// The library and its random number generator initialised, as C's
    /// global init does (`mbedtls_init`): whether it could.
    pub(crate) fn init() -> bool {
        MBEDTLS.init()
    }

    /// The library let go, as C's last cleanup does (`mbedtls_cleanup`).
    pub(crate) fn cleanup() {
        MBEDTLS.cleanup();
    }

    /// Its version as the version string names it: `mbedTLS/3.6.7`.
    pub(crate) fn version() -> impl fmt::Display {
        curl_mbedtls::version()
    }

    /// None: no QUIC over mbedTLS.
    pub(crate) fn quic() -> Option<&'static str> {
        None
    }
}

#[cfg(feature = "wolfssl")]
mod library {
    use super::*;

    /// wolfSSL, logging secrets to the root's key log, which its global
    /// init opens (`wssl_init`).
    pub(crate) static TLS: curl_wolfssl::WolfSsl = curl_wolfssl::WolfSsl::logging_keys_to(
        curl_core::tls::SharedKeyLog::of_static(&crate::root::KEYLOG),
    );

    pub(crate) const ED25519: Option<&'static dyn curl_core::libraries::Ed25519> =
        Some(&curl_wolfssl::ED25519);
    pub(crate) const H3: Option<&'static dyn curl_core::http3::Http3> = None;

    pub(crate) const ID: ffi::curl_sslbackend = ffi::CURLSSLBACKEND_WOLFSSL;
    pub(crate) const NAME: &CStr = c"wolfssl";

    /// The key log opened, then the library and its BIO method
    /// initialised, as C's global init does (`wssl_init`): whether it
    /// could.
    pub(crate) fn init() -> bool {
        crate::root::KEYLOG.open();
        TLS.init()
    }

    /// The library let go, as C's last cleanup does (`wssl_cleanup`); the
    /// root closes the key log.
    pub(crate) fn cleanup() {
        TLS.cleanup();
    }

    /// Its version as the version string names it: `wolfSSL/5.9.4`.
    pub(crate) fn version() -> impl fmt::Display {
        curl_wolfssl::version()
    }

    /// None: no QUIC over wolfSSL here.
    pub(crate) fn quic() -> Option<&'static str> {
        None
    }
}

#[cfg(feature = "schannel")]
mod library {
    use super::*;

    pub(crate) static TLS: curl_schannel::Schannel = curl_schannel::Schannel;

    pub(crate) const ED25519: Option<&'static dyn curl_core::libraries::Ed25519> = None;
    pub(crate) const H3: Option<&'static dyn curl_core::http3::Http3> = None;

    pub(crate) const ID: ffi::curl_sslbackend = ffi::CURLSSLBACKEND_SCHANNEL;
    pub(crate) const NAME: &CStr = c"schannel";

    /// Nothing: Schannel is the system's, and logs no keys.
    pub(crate) fn init() -> bool {
        true
    }

    /// Nothing.
    pub(crate) fn cleanup() {}

    /// `Schannel`, as C's `schannel_version` says it.
    pub(crate) fn version() -> impl fmt::Display {
        "Schannel"
    }

    /// None: no QUIC.
    pub(crate) fn quic() -> Option<&'static str> {
        None
    }
}

pub(crate) use library::*;
