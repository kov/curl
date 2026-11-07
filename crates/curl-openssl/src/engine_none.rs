//! The crypto engine a transfer names, where the library has neither
//! engines nor providers (LibreSSL, AWS-LC and BoringSSL: `OPENSSL_NO_ENGINE`,
//! and no OpenSSL 3): none is found, as C's build without `USE_OPENSSL_ENGINE`
//! and `OPENSSL_HAS_PROVIDERS` finds none, and none is listed.

use curl_alloc::OutOfMemory;
use curl_core::error::ErrorKind;
use curl_core::tls::TlsCx;
use openssl_sys::{SSL_CTX, SSL_METHOD};

/// No engine or provider: there is none to select.
#[derive(Default)]
pub(crate) struct Crypto {
    _none: (),
}

impl Crypto {
    /// None is found (`ossl_set_engine`), said as C says it: 53.
    pub(crate) fn select(_name: &[u8], io: &mut TlsCx<'_>) -> Result<Crypto, ErrorKind> {
        Err(io.fail(
            ErrorKind::SslEngineNotfound,
            format_args!("OpenSSL engine not found"),
        ))
    }

    /// Nothing to make the default (`ossl_set_engine_default`).
    pub(crate) fn set_default(&self, _io: &mut TlsCx<'_>) -> Result<(), ErrorKind> {
        Ok(())
    }

    /// No provider's library context is in use (`USING_PROVIDER`).
    pub(crate) fn has_libctx(&self) -> bool {
        false
    }

    /// No library context to make a context of `method` in: the library's
    /// own is used.
    pub(crate) fn libctx_ctx(&self, _method: *const SSL_METHOD) -> Option<*mut SSL_CTX> {
        None
    }
}

/// What a client certificate's type asks of an engine or a provider.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Wanted {
    Certificate,
    PrivateKey,
}

/// No engines (`ossl_engines_list`).
pub(crate) fn ids() -> Result<Vec<Vec<u8>>, OutOfMemory> {
    Ok(Vec::new())
}
