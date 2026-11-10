//! The TLS library this build has, as curl-backends' features chose it:
//! the process's part of it, which the tool initialises as C's global
//! init does and makes each of its `Libraries`' library from, logging to
//! the tool's own key log.

use core::fmt;

use curl_alloc::OutOfMemory;
use curl_backends::tls;
use curl_core::tls::{CaDefaults, SharedKeyLog, TlsBackend, TlsSupport};

/// The library's process-wide state (mbedTLS's random number generator,
/// wolfSSL's BIO method), which `init` makes.
static TLS: tls::Tls = tls::new();

/// The library, logging the secrets of its connections to `keylog`.
pub(crate) fn tls(keylog: &SharedKeyLog) -> Result<Box<dyn TlsBackend>, OutOfMemory> {
    tls::owned(&TLS, keylog)
}

/// The library initialised, as C's global init does: whether it could.
pub(crate) fn init() -> bool {
    tls::init(&TLS)
}

/// Whether the key log is opened as the library is initialised: where
/// C's library opens it (`ossl_init`, `wssl_init`), and with Schannel,
/// whose library logs no keys, as with OpenSSL.
pub(crate) const KEYLOG_AT_INIT: bool = tls::KEYLOG_AT_INIT || cfg!(feature = "schannel");

/// Its crypto engines' ids.
pub(crate) fn engines() -> Result<Vec<Vec<u8>>, OutOfMemory> {
    TLS.engines()
}

/// Its version as the version string names it: `OpenSSL/3.5.9`.
pub(crate) fn version() -> impl fmt::Display {
    tls::version()
}

/// The QUIC libraries, as the version string names them.
pub(crate) fn quic() -> Option<impl fmt::Display> {
    tls::quic_version()
}

/// What it can do past the handshake.
pub(crate) fn support() -> TlsSupport {
    TLS.support()
}

/// What it trusts where a transfer names nothing.
pub(crate) fn ca_defaults() -> CaDefaults {
    TLS.ca_defaults()
}

/// What the library claims with this TLS library (`curl_version_info`):
/// the core's, with what the TLS library decides, Encrypted Client Hello.
pub(crate) fn version_info() -> &'static curl_core::version::VersionInfo {
    curl_core::version::version_with_tls(&support())
}
