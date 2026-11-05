//! The TLS library this build has, one of two chosen as it is built:
//! OpenSSL (the `openssl` feature), with HTTP/3 over ngtcp2 and Ed25519
//! for message signatures, or Schannel (`schannel`, Windows only), with
//! neither, as C's build with it has neither.

use core::fmt;

use curl_alloc::{OutOfMemory, try_box};
use curl_core::tls::{SharedKeyLog, TlsBackend};

#[cfg(all(feature = "openssl", feature = "schannel"))]
compile_error!("one TLS library: the `openssl` and `schannel` features exclude each other");
#[cfg(not(any(feature = "openssl", feature = "schannel")))]
compile_error!("a TLS library: the `openssl` feature or the `schannel` one");

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

    /// Read its configuration, as C's global init does (`ossl_init`).
    pub(crate) fn init() {
        curl_openssl::init();
    }

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

    /// The options it lacks the support of: none.
    pub(crate) const LACKS: &[&str] = &[];
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
    pub(crate) fn init() {}

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

    /// The options it lacks the support of, which libcurl refuses as not
    /// built in (its `Curl_ssl_supports`), by the names the tool sets
    /// them by.
    pub(crate) const LACKS: &[&str] = &[
        "CURLOPT_CAPATH",
        "CURLOPT_PROXY_CAPATH",
        "CURLOPT_CRLFILE",
        "CURLOPT_PROXY_CRLFILE",
        "CURLOPT_ISSUERCERT",
        "CURLOPT_PROXY_ISSUERCERT",
        "CURLOPT_TLS13_CIPHERS",
        "CURLOPT_PROXY_TLS13_CIPHERS",
        "CURLOPT_SSL_EC_CURVES",
        "CURLOPT_SSL_SIGNATURE_ALGORITHMS",
    ];
}

/// Whether the library lacks the option named `name`.
pub(crate) fn lacks(name: &str) -> bool {
    LACKS.contains(&name)
}

pub(crate) use library::*;
