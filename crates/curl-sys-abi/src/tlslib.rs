//! The TLS library this build has, one of two chosen as it is built:
//! OpenSSL (the `openssl` feature), with HTTP/3 over ngtcp2 and Ed25519
//! for message signatures, or Schannel (`schannel`, Windows only), with
//! neither, as C's build with it has neither.

use core::ffi::CStr;
use core::fmt;

use crate::ffi;

#[cfg(all(feature = "openssl", feature = "schannel"))]
compile_error!("one TLS library: the `openssl` and `schannel` features exclude each other");
#[cfg(not(any(feature = "openssl", feature = "schannel")))]
compile_error!("a TLS library: the `openssl` feature or the `schannel` one");

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
    /// does (`ossl_init`).
    pub(crate) fn init() {
        curl_openssl::init();
        crate::root::KEYLOG.open();
    }

    /// Its version as the version string names it: `OpenSSL/3.5.9`.
    pub(crate) fn version() -> impl fmt::Display {
        curl_openssl::version()
    }

    /// The QUIC libraries, as `quic_version` names them.
    pub(crate) fn quic() -> Option<impl fmt::Display> {
        Some(curl_ngtcp2::version())
    }

    /// The options it lacks the support of (`Curl_ssl_supports`): none.
    pub(crate) const LACKS: &[ffi::CURLoption] = &[];
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
    pub(crate) fn init() {}

    /// `Schannel`, as C's `schannel_version` says it.
    pub(crate) fn version() -> impl fmt::Display {
        "Schannel"
    }

    /// None: no QUIC.
    pub(crate) fn quic() -> Option<&'static str> {
        None
    }

    /// The options it lacks the support of, which setting refuses as not
    /// built in (`Curl_ssl_supports`): Schannel's `supports` has no
    /// `SSLSUPP_CA_PATH`, `_CRLFILE`, `_ISSUERCERT`, `_ISSUERCERT_BLOB`,
    /// `_TLS13_CIPHERSUITES`, `_SSL_CTX`, `_SSL_EC_CURVES` nor
    /// `_SIGNATURE_ALGORITHMS`.
    pub(crate) const LACKS: &[ffi::CURLoption] = &[
        ffi::CURLOPT_CAPATH,
        ffi::CURLOPT_PROXY_CAPATH,
        ffi::CURLOPT_CRLFILE,
        ffi::CURLOPT_PROXY_CRLFILE,
        ffi::CURLOPT_ISSUERCERT,
        ffi::CURLOPT_PROXY_ISSUERCERT,
        ffi::CURLOPT_ISSUERCERT_BLOB,
        ffi::CURLOPT_PROXY_ISSUERCERT_BLOB,
        ffi::CURLOPT_TLS13_CIPHERS,
        ffi::CURLOPT_PROXY_TLS13_CIPHERS,
        ffi::CURLOPT_SSL_CTX_FUNCTION,
        ffi::CURLOPT_SSL_CTX_DATA,
        ffi::CURLOPT_SSL_EC_CURVES,
        ffi::CURLOPT_SSL_SIGNATURE_ALGORITHMS,
    ];
}

pub(crate) use library::*;
