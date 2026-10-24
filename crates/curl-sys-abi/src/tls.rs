//! The application's hands on OpenSSL (`lib/vtls/openssl.c`): the
//! `SSL_CTX` function and its data (`CURLOPT_SSL_CTX_FUNCTION`,
//! `CURLOPT_SSL_CTX_DATA`), and the `SSL_CTX` and `SSL` of a transfer's
//! connection (`CURLINFO_TLS_SESSION`, `CURLINFO_TLS_SSL_PTR`). The core
//! hands out its TLS library's objects as an opaque `TlsNative`; here
//! they become the C pointers, with the backend C names them by.

#![allow(unsafe_code)]

use core::ffi::c_void;
use core::ptr::{self, NonNull};

use curl_alloc::OutOfMemory;
use curl_core::error::ErrorKind;
use curl_core::handler::{Handler, TlsContextHandler};
use curl_core::multi::TransferCx;
use curl_core::options::Options;
use curl_core::tls::TlsNative;

use crate::callbacks::Adapter;
use crate::easy::ShimEasy;
use crate::error_codes::easy_code;
use crate::ffi::{self, CURLE_OK, CURLINFO, CURLcode, curl_ssl_ctx_callback};
use crate::gate::Recursive;

/// The application's `SSL_CTX` function and data, as setopt left them.
#[derive(Clone, Copy)]
pub(crate) struct CTls {
    pub(crate) ctx: curl_ssl_ctx_callback,
    pub(crate) ctx_data: *mut c_void,
}

impl CTls {
    /// None set, as a new handle has (`Curl_init_userdefined`).
    pub(crate) const NONE: CTls = CTls {
        ctx: None,
        ctx_data: ptr::null_mut(),
    };
}

/// The context handler for `c` in `options`: one that calls through
/// `easy` while the application has a function set, else none.
pub(crate) fn sync(
    options: &mut Options,
    easy: NonNull<ShimEasy>,
    c: &CTls,
) -> Result<(), OutOfMemory> {
    let tls = &mut options.tls.options;
    let handler = match c.ctx {
        Some(_) => Some(Handler::tls_context(Adapter(easy))?),
        None if tls.made_mut().is_none() => return Ok(()),
        None => None,
    };
    match tls.made_mut() {
        Some(made) => made.context = handler,
        None => tls.make_mut()?.context = handler,
    }
    Ok(())
}

/// What an `SSL_CTX` function's code comes to: `CURLE_OK` goes on, any
/// code a transfer ends with fails it with that code. One no transfer
/// ends with (`CURLE_AGAIN`, which trips an assertion in C, an
/// API-only code or a number past them, which C returns as it is) fails
/// it as aborted by the callback (DIVERGENCE.md).
fn transfer_result(code: CURLcode) -> Result<(), ErrorKind> {
    if code == CURLE_OK {
        return Ok(());
    }
    let kind = ErrorKind::ALL.iter().find(|&&k| easy_code(k) == code);
    Err(kind.copied().unwrap_or(ErrorKind::AbortedByCallback))
}

impl TlsContextHandler for Adapter {
    /// The function with the handle, the `SSL_CTX` and the data, as
    /// the application set them when the context is made
    /// (`ossl_init_ctx`'s call of `set.ssl_fsslctx`).
    fn configure(&self, cx: &mut TransferCx<'_>, native: TlsNative) -> Result<(), ErrorKind> {
        let c = self.easy().tls();
        // Cleared since the transfer started: C calls none.
        let Some(f) = c.ctx else {
            return Ok(());
        };
        let handle = self.handle();
        let ctx = native.context().as_ptr();
        // SAFETY: the application's function, of the option's type, given
        // its handle, OpenSSL's `SSL_CTX` and its data, as C gives them.
        let code = self.call(cx, || unsafe { f(handle.cast(), ctx, c.ctx_data) });
        transfer_result(code)
    }
}

/// `CURLINFO_TLS_SSL_PTR` and `CURLINFO_TLS_SESSION`: the handle's
/// `curl_tlssessioninfo`, naming OpenSSL and holding the `SSL` (or, for
/// the session, the `SSL_CTX`) of the connection the transfer holds, or
/// NULL while it holds none (`Curl_conn_get_ssl_info`).
pub(crate) fn session_info(
    easy: &ShimEasy,
    info: CURLINFO,
) -> Result<*mut ffi::curl_tlssessioninfo, Recursive> {
    let native = easy.tls_native()?;
    let internals = native.and_then(|n| {
        if info == ffi::CURLINFO_TLS_SSL_PTR {
            n.session()
        } else {
            Some(n.context())
        }
    });
    let tsi = easy.tsi.get();
    // SAFETY: the handle's own, which the application reads only once
    // getinfo returns, and no other call writes meanwhile.
    unsafe {
        tsi.write(ffi::curl_tlssessioninfo {
            backend: ffi::CURLSSLBACKEND_OPENSSL,
            internals: internals.map_or(ptr::null_mut(), NonNull::as_ptr),
        })
    };
    Ok(tsi)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A code a transfer ends with is the transfer's; one none ends with
    /// is an abort by the callback.
    #[test]
    fn a_function_s_code_is_the_transfer_s_if_it_can_be() {
        assert_eq!(transfer_result(CURLE_OK), Ok(()));
        assert_eq!(
            transfer_result(ffi::CURLE_SSL_CERTPROBLEM),
            Err(ErrorKind::SslCertproblem)
        );
        assert_eq!(
            transfer_result(ffi::CURLE_OUT_OF_MEMORY),
            Err(ErrorKind::OutOfMemory)
        );
        for code in [
            ffi::CURLE_AGAIN,
            ffi::CURLE_UNKNOWN_OPTION,
            ffi::CURLE_RECURSIVE_API_CALL,
            CURLcode(1000),
        ] {
            assert_eq!(transfer_result(code), Err(ErrorKind::AbortedByCallback));
        }
    }
}
