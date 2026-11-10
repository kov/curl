//! The TLS library this build has, as curl-backends' features chose it,
//! held as the process's: a static logging to the root's key log. What
//! is the C ABI's alone is here too: the library's id and name, as
//! `curl_global_sslset` and `CURLINFO_TLS_SSL_PTR` give them.

use core::ffi::CStr;

use curl_backends::tls;
use curl_core::tls::TlsKind;

use crate::ffi;

/// The library, logging secrets to the root's key log.
pub(crate) static TLS: tls::Tls = tls::logging_keys_to(&crate::root::KEYLOG);

/// Its id and name, as C names them.
pub(crate) const ID: ffi::curl_sslbackend = c_names(tls::KIND).0;
pub(crate) const NAME: &CStr = c_names(tls::KIND).1;

/// The id and name C gives each library's backend.
const fn c_names(kind: TlsKind) -> (ffi::curl_sslbackend, &'static CStr) {
    match kind {
        TlsKind::OpenSsl => (ffi::CURLSSLBACKEND_OPENSSL, c"openssl"),
        TlsKind::GnuTls => (ffi::CURLSSLBACKEND_GNUTLS, c"gnutls"),
        TlsKind::MbedTls => (ffi::CURLSSLBACKEND_MBEDTLS, c"mbedtls"),
        TlsKind::WolfSsl => (ffi::CURLSSLBACKEND_WOLFSSL, c"wolfssl"),
        TlsKind::Rustls => (ffi::CURLSSLBACKEND_RUSTLS, c"rustls"),
        TlsKind::Schannel => (ffi::CURLSSLBACKEND_SCHANNEL, c"schannel"),
        TlsKind::Other => panic!("a build links one of the libraries C has a backend for"),
    }
}

/// The key log opened where C's global init opens it (`ossl_init`,
/// `wssl_init`), then the library initialised: whether it could be.
pub(crate) fn init() -> bool {
    if tls::KEYLOG_AT_INIT {
        crate::root::KEYLOG.open();
    }
    tls::init(&TLS)
}

/// The library let go, as C's last cleanup does; the root closes the key
/// log.
pub(crate) fn cleanup() {
    tls::cleanup(&TLS);
}

pub(crate) use tls::{quic_version as quic, version};
