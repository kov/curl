//! The TLS library this build has, one of six chosen as it is built:
//! OpenSSL (the `openssl` feature), with HTTP/3 over ngtcp2 and Ed25519
//! for message signatures, or over quiche (`quiche`, both meaning
//! `openssl-tls`); GnuTLS (`gnutls`) or wolfSSL (`wolfssl`), with
//! HTTP/3 over ngtcp2 and Ed25519; or mbedTLS (`mbedtls`), Rustls
//! (`rustls`) or Schannel (`schannel`, Windows only), with neither, as
//! C's builds with them have.
//!
//! The library is a value, [`Tls`], which some libraries make sessions
//! from only once [`init`] has run on it (mbedTLS's random number
//! generator, wolfSSL's BIO method). A process keeps one in a static:
//! the shim's logs keys to the process's key log
//! ([`logging_keys_to`]) and is handed out itself; an owner of its own
//! keeps one logging none ([`new`]) and hands each `Libraries` one made
//! from it, logging to its key log ([`owned`]).

use core::fmt;

use curl_alloc::{OutOfMemory, try_box};
use curl_core::http3::Http3;
use curl_core::libraries::Ed25519;
use curl_core::tls::{KeyLog, SharedKeyLog, TlsBackend, TlsKind};

#[cfg(any(
    all(feature = "openssl", feature = "quiche"),
    all(feature = "openssl-tls", feature = "gnutls"),
    all(feature = "openssl-tls", feature = "mbedtls"),
    all(feature = "openssl-tls", feature = "wolfssl"),
    all(feature = "openssl-tls", feature = "schannel"),
    all(feature = "openssl-tls", feature = "rustls"),
    all(feature = "gnutls", feature = "mbedtls"),
    all(feature = "gnutls", feature = "wolfssl"),
    all(feature = "gnutls", feature = "schannel"),
    all(feature = "gnutls", feature = "rustls"),
    all(feature = "mbedtls", feature = "wolfssl"),
    all(feature = "mbedtls", feature = "schannel"),
    all(feature = "mbedtls", feature = "rustls"),
    all(feature = "wolfssl", feature = "schannel"),
    all(feature = "wolfssl", feature = "rustls"),
    all(feature = "schannel", feature = "rustls")
))]
compile_error!(
    "one TLS library: the `openssl` (or `quiche`), `gnutls`, `mbedtls`, `wolfssl`, `rustls` \
     and `schannel` features exclude each other"
);
#[cfg(not(any(
    feature = "openssl-tls",
    feature = "gnutls",
    feature = "mbedtls",
    feature = "wolfssl",
    feature = "schannel",
    feature = "rustls"
)))]
compile_error!(
    "a TLS library: the `openssl`, `gnutls`, `mbedtls`, `wolfssl`, `rustls` or `schannel` \
     feature"
);
#[cfg(all(
    feature = "openssl-tls",
    not(any(feature = "openssl", feature = "quiche"))
))]
compile_error!("OpenSSL with a QUIC library: the `openssl` or the `quiche` feature");

/// Whether C's global init opens the key log (`ossl_init`, `wssl_init`):
/// the other libraries open it as each session or configuration is made
/// (GnuTLS, Rustls), or never (mbedTLS, Schannel).
pub const KEYLOG_AT_INIT: bool = cfg!(any(feature = "openssl-tls", feature = "wolfssl"));

#[cfg(feature = "openssl-tls")]
mod library {
    use super::*;

    pub type Tls = curl_openssl::OpenSsl;
    pub const KIND: TlsKind = TlsKind::OpenSsl;

    pub const fn new() -> Tls {
        curl_openssl::OpenSsl::new()
    }

    pub const fn logging_keys_to(keylog: &'static KeyLog) -> Tls {
        curl_openssl::OpenSsl::logging_keys_to(SharedKeyLog::of_static(keylog))
    }

    /// Its configuration read (`ossl_init`).
    pub fn init(_: &Tls) -> bool {
        curl_openssl::init();
        true
    }

    /// Nothing to let go of.
    pub fn cleanup(_: &Tls) {}

    pub fn owned(
        _: &'static Tls,
        keylog: &SharedKeyLog,
    ) -> Result<Box<dyn TlsBackend>, OutOfMemory> {
        Ok(try_box(curl_openssl::OpenSsl::logging_keys_to(
            keylog.clone(),
        ))?)
    }

    pub const ED25519: Option<&'static dyn Ed25519> = Some(&curl_openssl::ED25519);
    #[cfg(feature = "openssl")]
    pub const H3: Option<&'static dyn Http3> = Some(&curl_ngtcp2::NGTCP2);
    #[cfg(feature = "quiche")]
    pub const H3: Option<&'static dyn Http3> = Some(&curl_quiche::QUICHE);

    /// `OpenSSL/3.5.9`.
    pub fn version() -> impl fmt::Display {
        curl_openssl::version()
    }

    #[cfg(feature = "openssl")]
    pub fn quic_version() -> Option<impl fmt::Display> {
        Some(curl_ngtcp2::version())
    }

    #[cfg(feature = "quiche")]
    pub fn quic_version() -> Option<impl fmt::Display> {
        Some(curl_quiche::version())
    }
}

#[cfg(feature = "gnutls")]
mod library {
    use super::*;

    pub type Tls = curl_gnutls::GnuTls;
    pub const KIND: TlsKind = TlsKind::GnuTls;

    pub const fn new() -> Tls {
        curl_gnutls::GnuTls::new()
    }

    /// GnuTLS logging to `keylog`, which its sessions open as they are
    /// made (`Curl_gtls_ctx_init`).
    pub const fn logging_keys_to(keylog: &'static KeyLog) -> Tls {
        curl_gnutls::GnuTls::logging_keys_to(SharedKeyLog::of_static(keylog))
    }

    /// The library initialised (`gtls_init`).
    pub fn init(_: &Tls) -> bool {
        curl_gnutls::init()
    }

    /// The library let go (`gtls_cleanup`).
    pub fn cleanup(_: &Tls) {
        curl_gnutls::cleanup();
    }

    pub fn owned(
        _: &'static Tls,
        keylog: &SharedKeyLog,
    ) -> Result<Box<dyn TlsBackend>, OutOfMemory> {
        Ok(try_box(curl_gnutls::GnuTls::logging_keys_to(
            keylog.clone(),
        ))?)
    }

    pub const ED25519: Option<&'static dyn Ed25519> = Some(&curl_gnutls::ED25519);
    /// HTTP/3 over ngtcp2's GnuTLS crypto.
    pub const H3: Option<&'static dyn Http3> = Some(&curl_ngtcp2::NGTCP2);

    /// `GnuTLS/3.8.13`.
    pub fn version() -> impl fmt::Display {
        curl_gnutls::version()
    }

    pub fn quic_version() -> Option<impl fmt::Display> {
        Some(curl_ngtcp2::version())
    }
}

#[cfg(feature = "mbedtls")]
mod library {
    use super::*;

    pub type Tls = curl_mbedtls::MbedTls;
    pub const KIND: TlsKind = TlsKind::MbedTls;

    pub const fn new() -> Tls {
        curl_mbedtls::MbedTls::new()
    }

    /// mbedTLS, which logs no secrets: C's build never opens the log.
    pub const fn logging_keys_to(_: &'static KeyLog) -> Tls {
        curl_mbedtls::MbedTls::new()
    }

    /// The library and its random number generator initialised
    /// (`mbedtls_init`).
    pub fn init(tls: &Tls) -> bool {
        tls.init()
    }

    /// The library let go (`mbedtls_cleanup`).
    pub fn cleanup(tls: &Tls) {
        tls.cleanup();
    }

    /// `tls` itself, whose generator every session draws on; it logs no
    /// secrets.
    pub fn owned(tls: &'static Tls, _: &SharedKeyLog) -> Result<Box<dyn TlsBackend>, OutOfMemory> {
        Ok(try_box(tls)?)
    }

    pub const ED25519: Option<&'static dyn Ed25519> = None;
    pub const H3: Option<&'static dyn Http3> = None;

    /// `mbedTLS/3.6.7`.
    pub fn version() -> impl fmt::Display {
        curl_mbedtls::version()
    }

    /// None: no QUIC over mbedTLS.
    pub fn quic_version() -> Option<&'static str> {
        None
    }
}

#[cfg(feature = "wolfssl")]
mod library {
    use super::*;

    pub type Tls = curl_wolfssl::WolfSsl;
    pub const KIND: TlsKind = TlsKind::WolfSsl;

    pub const fn new() -> Tls {
        curl_wolfssl::WolfSsl::new()
    }

    pub const fn logging_keys_to(keylog: &'static KeyLog) -> Tls {
        curl_wolfssl::WolfSsl::logging_keys_to(SharedKeyLog::of_static(keylog))
    }

    /// The library and its BIO method initialised (`wssl_init`).
    pub fn init(tls: &Tls) -> bool {
        tls.init()
    }

    /// The library let go (`wssl_cleanup`).
    pub fn cleanup(tls: &Tls) {
        tls.cleanup();
    }

    /// The library as `tls` initialised it, its BIO method shared.
    pub fn owned(
        tls: &'static Tls,
        keylog: &SharedKeyLog,
    ) -> Result<Box<dyn TlsBackend>, OutOfMemory> {
        Ok(try_box(tls.with_keylog(keylog.clone()))?)
    }

    pub const ED25519: Option<&'static dyn Ed25519> = Some(&curl_wolfssl::ED25519);
    /// HTTP/3 over ngtcp2's wolfSSL crypto.
    pub const H3: Option<&'static dyn Http3> = Some(&curl_ngtcp2::NGTCP2);

    /// `wolfSSL/5.9.4`.
    pub fn version() -> impl fmt::Display {
        curl_wolfssl::version()
    }

    pub fn quic_version() -> Option<impl fmt::Display> {
        Some(curl_ngtcp2::version())
    }
}

#[cfg(feature = "rustls")]
mod library {
    use super::*;

    pub type Tls = curl_rustls::Rustls;
    pub const KIND: TlsKind = TlsKind::Rustls;

    pub const fn new() -> Tls {
        curl_rustls::Rustls::new()
    }

    /// Rustls logging to `keylog`, which each connection opens as its
    /// configuration is built (`init_config_builder_keylog`).
    pub const fn logging_keys_to(keylog: &'static KeyLog) -> Tls {
        curl_rustls::Rustls::logging_keys_to(SharedKeyLog::of_static(keylog))
    }

    /// Nothing to set up: C's has no init.
    pub fn init(_: &Tls) -> bool {
        true
    }

    /// Nothing to let go of but the key log, which its owner closes
    /// (`cr_cleanup`).
    pub fn cleanup(_: &Tls) {}

    pub fn owned(
        _: &'static Tls,
        keylog: &SharedKeyLog,
    ) -> Result<Box<dyn TlsBackend>, OutOfMemory> {
        Ok(try_box(curl_rustls::Rustls::logging_keys_to(
            keylog.clone(),
        ))?)
    }

    pub const ED25519: Option<&'static dyn Ed25519> = None;
    pub const H3: Option<&'static dyn Http3> = None;

    /// `rustls-ffi/0.15.5/rustls/0.23.46/aws-lc-rs`.
    pub fn version() -> impl fmt::Display {
        curl_rustls::version()
    }

    /// None: no QUIC over Rustls.
    pub fn quic_version() -> Option<&'static str> {
        None
    }
}

#[cfg(feature = "schannel")]
mod library {
    use super::*;

    pub type Tls = curl_schannel::Schannel;
    pub const KIND: TlsKind = TlsKind::Schannel;

    pub const fn new() -> Tls {
        curl_schannel::Schannel
    }

    /// Schannel, which logs no secrets.
    pub const fn logging_keys_to(_: &'static KeyLog) -> Tls {
        curl_schannel::Schannel
    }

    /// Nothing: Schannel is the system's.
    pub fn init(_: &Tls) -> bool {
        true
    }

    /// Nothing.
    pub fn cleanup(_: &Tls) {}

    pub fn owned(_: &'static Tls, _: &SharedKeyLog) -> Result<Box<dyn TlsBackend>, OutOfMemory> {
        Ok(try_box(curl_schannel::Schannel)?)
    }

    pub const ED25519: Option<&'static dyn Ed25519> = None;
    pub const H3: Option<&'static dyn Http3> = None;

    /// `Schannel`, as C's `schannel_version` says it.
    pub fn version() -> impl fmt::Display {
        "Schannel"
    }

    /// None: no QUIC.
    pub fn quic_version() -> Option<&'static str> {
        None
    }
}

/// The library's type: `OpenSsl`, `GnuTls`, `MbedTls`, `WolfSsl`,
/// `Rustls` or `Schannel`.
pub use library::Tls;

/// Which library it is, as the C ABI's backend ids tell them apart.
pub use library::KIND;

/// The library logging no secrets, not yet initialised: what an owner of
/// its own `Libraries` keeps in a static, initialises (`init`) and makes
/// each `Libraries`' library from (`owned`).
pub use library::new;

/// The library logging the secrets of its connections to `keylog`
/// (`SSLKEYLOGFILE`) while it is open, if it logs any, not yet
/// initialised: what a process whose key log is a static keeps in one,
/// initialises (`init`) and hands out itself (`Library::Static`).
pub use library::logging_keys_to;

/// Initialise the library in `tls`, as C's global init does
/// (`Curl_ssl_init`): whether it could. Each successful call is matched
/// by `cleanup`'s. The key log is the caller's to open
/// ([`KEYLOG_AT_INIT`]).
pub use library::init;

/// Let the library in `tls` go, as C's last global cleanup does.
pub use library::cleanup;

/// The library `tls` initialised, logging the secrets of its connections
/// to `keylog`, for a `Libraries` of its own (`Library::Owned`).
pub use library::owned;

/// What signs HTTP message signatures under Ed25519 with this library, if
/// anything does.
pub use library::ED25519;

/// The HTTP/3 library over this TLS library, if any: ngtcp2 with this
/// library's crypto, or quiche over OpenSSL's fork.
pub use library::H3;

/// The library's version as curl's version string names it.
pub use library::version;

/// The QUIC libraries' versions as curl's version string names them, if
/// the build has any.
pub use library::quic_version;
