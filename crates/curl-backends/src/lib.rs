//! The C libraries a build of curl is linked with, chosen once by this
//! crate's features, and the core's `Libraries` made of them: which TLS
//! library, with which QUIC library and crypto, which SSH library,
//! resolver, IDN and GSS-API. The C ABI shim and the tool pass their
//! features through to these, so neither writes the pairing itself, and a
//! Rust application gets the same from [`libraries`].
//!
//! What differs between owners is how the TLS library is held: the shim's
//! is a static logging to the process's key log ([`tls::logging_keys_to`],
//! handed out as `Library::Static`); an owner of its own, as the tool is,
//! keeps a static of the library's process-wide state ([`tls::new`]) and
//! gives each `Libraries` one logging to its own key log ([`tls::owned`]).
//!
//! ```ignore
//! static TLS: curl_backends::tls::Tls = curl_backends::tls::new();
//! assert!(curl_backends::tls::init(&TLS));
//! let keylog = SharedKeyLog::new()?;
//! let tls = curl_backends::tls::owned(&TLS, &keylog)?;
//! let libraries = curl_backends::libraries(
//!     Library::Owned(tls),
//!     Some(curl_backends::SECURITY),
//!     None,
//! );
//! easy.set_libraries(SharedLibraries::new(libraries)?);
//! ```

#![forbid(unsafe_code)]

use curl_core::libraries::{Libraries, Library, Random, Security};
use curl_core::tls::TlsBackend;

pub mod dns;
pub mod ssh;
pub mod tls;

// The libraries the features chose, for what is particular to one of them
// (their versions as C's version string spells them, their own statics).
#[cfg(feature = "c-ares")]
pub use curl_ares;
#[cfg(feature = "gnutls")]
pub use curl_gnutls;
#[cfg(feature = "libssh")]
pub use curl_libssh;
#[cfg(feature = "libssh2")]
pub use curl_libssh2;
#[cfg(feature = "mbedtls")]
pub use curl_mbedtls;
#[cfg(any(feature = "openssl", feature = "gnutls", feature = "wolfssl"))]
pub use curl_ngtcp2;
#[cfg(feature = "openssl-tls")]
pub use curl_openssl;
#[cfg(feature = "quiche")]
pub use curl_quiche;
#[cfg(feature = "rustls")]
pub use curl_rustls;
#[cfg(feature = "schannel")]
pub use curl_schannel;
#[cfg(feature = "wolfssl")]
pub use curl_wolfssl;

/// What Kerberos and SPNEGO go through: MIT krb5's or GNU GSS's GSS-API,
/// or on Windows SSPI, as every C build for Windows has it.
#[cfg(not(windows))]
pub const SECURITY: Security = Security::Gss(&curl_gssapi::GSSAPI);
#[cfg(windows)]
pub const SECURITY: Security = Security::Sspi(&curl_sspi::SSPI);

/// What converts host names, for handles and the URL API alike.
pub const IDN: &dyn curl_core::idn::Idn = curl_idn2::IDN;

/// The libraries this build is linked with, as a handle is given them:
/// the content codings they undo, the TLS library `tls` (this build's,
/// as the caller holds it: see [`tls`]) with the HTTP/3 library and the
/// Ed25519 that go with it, `security` (this build's [`SECURITY`], where
/// the build claims Kerberos), and the rest as the features chose them.
/// `random` stands in for the system's random bytes, if anything does.
///
/// `const`, for a process that keeps its libraries in a static.
pub const fn libraries(
    tls: Library<dyn TlsBackend>,
    security: Option<Security>,
    random: Option<Library<dyn Random>>,
) -> Libraries {
    use curl_core::coding::{Coding, Decoders};
    Libraries {
        decoders: Decoders::none()
            .with(Coding::Deflate, curl_zlib::deflate)
            .with(Coding::Gzip, curl_zlib::gzip)
            .with(Coding::Brotli, curl_brotli::decoder)
            .with(Coding::Zstd, curl_zstd::decoder),
        ed25519: tls::ED25519,
        tls: Some(tls),
        security,
        dns: dns::LIBRARY,
        idn: Some(IDN),
        h2: Some(&curl_nghttp2::NGHTTP2),
        h3: tls::H3,
        ssh: Some(ssh::LIBRARY),
        ldap: curl_ldap::library(),
        psl: Some(&curl_psl::LIBPSL),
        random,
    }
}
