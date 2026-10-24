//! The crypto engine or provider a transfer names (`CURLOPT_SSLENGINE`,
//! `ossl_set_engine`): an engine of that id if the library has one, else
//! a provider of that name, `name[:properties]`, loaded into a library
//! context of the session's own, with the base provider beside it; made
//! the default for every algorithm if asked (`CURLOPT_SSLENGINE_DEFAULT`);
//! and the engines the library has (`CURLINFO_SSL_ENGINES`).

#![allow(unsafe_code)]

use core::ffi::{c_char, c_int, c_uint, c_void};
use core::ptr::{self, NonNull};

use curl_alloc::{OutOfMemory, TryVec as _};
use curl_core::error::ErrorKind;
use curl_core::tls::TlsIo;
use openssl_sys::{ENGINE, EVP_PKEY, OSSL_LIB_CTX, OSSL_PROVIDER, SSL_CTX, SSL_METHOD, X509};

use crate::x509::{ErrText, Text, c_string};

// SAFETY: the declarations are `engine.h`'s, `crypto.h`'s,
// `provider.h`'s and `ssl.h`'s; the library exports them.
unsafe extern "C" {
    fn ENGINE_get_first() -> *mut ENGINE;
    fn ENGINE_get_next(e: *mut ENGINE) -> *mut ENGINE;
    fn ENGINE_get_id(e: *const ENGINE) -> *const c_char;
    fn ENGINE_by_id(id: *const c_char) -> *mut ENGINE;
    fn ENGINE_init(e: *mut ENGINE) -> c_int;
    fn ENGINE_finish(e: *mut ENGINE) -> c_int;
    fn ENGINE_free(e: *mut ENGINE) -> c_int;
    fn ENGINE_set_default(e: *mut ENGINE, flags: c_uint) -> c_int;
    fn OSSL_LIB_CTX_load_config(ctx: *mut OSSL_LIB_CTX, file: *const c_char) -> c_int;
    fn OSSL_PROVIDER_available(ctx: *mut OSSL_LIB_CTX, name: *const c_char) -> c_int;
    fn SSL_CTX_new_ex(
        ctx: *mut OSSL_LIB_CTX,
        propq: *const c_char,
        method: *const SSL_METHOD,
    ) -> *mut SSL_CTX;
    fn OSSL_STORE_open_ex(
        uri: *const c_char,
        libctx: *mut OSSL_LIB_CTX,
        propq: *const c_char,
        ui_method: *const UiMethod,
        ui_data: *mut c_void,
        params: *const c_void,
        post_process: *const c_void,
        post_process_data: *mut c_void,
    ) -> *mut StoreCtx;
    fn OSSL_STORE_expect(ctx: *mut StoreCtx, expected_type: c_int) -> c_int;
    fn OSSL_STORE_load(ctx: *mut StoreCtx) -> *mut StoreInfo;
    fn OSSL_STORE_close(ctx: *mut StoreCtx) -> c_int;
    fn OSSL_STORE_INFO_get_type(info: *const StoreInfo) -> c_int;
    fn OSSL_STORE_INFO_get1_CERT(info: *const StoreInfo) -> *mut X509;
    fn OSSL_STORE_INFO_get1_PKEY(info: *const StoreInfo) -> *mut EVP_PKEY;
    fn OSSL_STORE_INFO_free(info: *mut StoreInfo);
    fn UI_OpenSSL() -> *mut UiMethod;
}

/// `OSSL_STORE_CTX`, `OSSL_STORE_INFO` and `UI_METHOD`, only ever pointed
/// to.
enum StoreCtx {}
enum StoreInfo {}
enum UiMethod {}

/// `OSSL_STORE_INFO_PKEY` and `OSSL_STORE_INFO_CERT` (`store.h`).
const STORE_INFO_PKEY: c_int = 4;
const STORE_INFO_CERT: c_int = 5;

/// `ENGINE_METHOD_ALL` (`engine.h`).
const ENGINE_METHOD_ALL: c_uint = 0xFFFF;

/// The longest provider name taken (`MAX_PROVIDER_LEN`).
const MAX_PROVIDER: usize = 128;

/// The engine, or the provider and its library context, a session's
/// context is made with; given back as it goes, after the context.
#[derive(Default)]
pub(crate) struct Crypto {
    engine: Option<NonNull<ENGINE>>,
    libctx: Option<NonNull<OSSL_LIB_CTX>>,
    /// The properties the provider is fetched with, a C string.
    propq: Option<Vec<u8>>,
    provider: Option<NonNull<OSSL_PROVIDER>>,
    base: Option<NonNull<OSSL_PROVIDER>>,
}

// SAFETY: an engine, a library context and its providers may be used
// from any thread, one at a time, which the session that owns them
// ensures; they move between threads only with it.
unsafe impl Send for Crypto {}

impl Crypto {
    /// The engine or provider `name` names (`ossl_set_engine`): 66 for an
    /// engine that will not start, 53 for neither, each said as C says it.
    pub(crate) fn select(name: &[u8], io: &mut TlsIo<'_>) -> Result<Crypto, ErrorKind> {
        let id = c_string(name)?;
        // SAFETY: a C string; the engine, if any, is this one's to free.
        let engine = unsafe { ENGINE_by_id(id.as_ptr().cast()) };
        let Some(engine) = NonNull::new(engine) else {
            return Crypto::provider(name, io);
        };
        // SAFETY: the engine found.
        if unsafe { ENGINE_init(engine.as_ptr()) } == 0 {
            // SAFETY: the reference `ENGINE_by_id` gave, given back once.
            unsafe { ENGINE_free(engine.as_ptr()) };
            let e = ErrText::last();
            return Err(io.fail(
                ErrorKind::SslEngineInitfailed,
                format_args!("Failed to initialize SSL Engine '{}': {e}", Text(name)),
            ));
        }
        let mut crypto = Crypto::default();
        crypto.engine = Some(engine);
        Ok(crypto)
    }

    /// The provider `name:properties` names, no engine looked for
    /// (`ossl_set_provider`, as a PKCS#11 URI's key reaches it).
    pub(crate) fn select_provider(given: &[u8], io: &mut TlsIo<'_>) -> Result<Crypto, ErrorKind> {
        Crypto::provider(given, io)
    }

    /// Nothing was selected.
    pub(crate) fn is_empty(&self) -> bool {
        self.engine.is_none() && self.libctx.is_none()
    }

    /// An engine was selected.
    pub(crate) fn has_engine(&self) -> bool {
        self.engine.is_some()
    }

    /// The provider `name:properties` names, loaded into a library
    /// context of its own with the base provider (`ossl_set_provider`).
    fn provider(given: &[u8], io: &mut TlsIo<'_>) -> Result<Crypto, ErrorKind> {
        let (name, propq) = match given.iter().position(|&b| b == b':') {
            Some(at) => (&given[..at], Some(&given[at + 1..])),
            None => (given, None),
        };
        if name.is_empty() || name.len() > MAX_PROVIDER {
            return Err(ErrorKind::BadFunctionArgument);
        }
        let name = c_string(name)?;
        let mut crypto = Crypto::default();
        crypto.propq = propq.map(c_string).transpose()?;
        // SAFETY: a new library context, this one's to free.
        let libctx = NonNull::new(unsafe { openssl_sys::OSSL_LIB_CTX_new() });
        let libctx = libctx.ok_or(ErrorKind::OutOfMemory)?;
        crypto.libctx = Some(libctx);
        let l = libctx.as_ptr();
        // SAFETY: the context; no file names the library's default.
        if unsafe { OSSL_LIB_CTX_load_config(l, ptr::null()) } == 0 {
            io.info(format_args!(
                "Failed to load default openssl config. Proceeding."
            ));
        }
        // SAFETY: the context and a C string.
        if unsafe { OSSL_PROVIDER_available(l, name.as_ptr().cast()) } != 0 {
            // Loaded by the configuration already.
            return Ok(crypto);
        }
        // SAFETY: as above; the provider, if any, is this one's to unload.
        let provider = unsafe { openssl_sys::OSSL_PROVIDER_try_load(l, name.as_ptr().cast(), 1) };
        let Some(provider) = NonNull::new(provider) else {
            let e = ErrText::last();
            return Err(io.fail(
                ErrorKind::SslEngineNotfound,
                format_args!("Failed to initialize provider: {e}"),
            ));
        };
        crypto.provider = Some(provider);
        // SAFETY: as above.
        let base = unsafe { openssl_sys::OSSL_PROVIDER_try_load(l, c"base".as_ptr(), 1) };
        let Some(base) = NonNull::new(base) else {
            return Err(io.fail(
                ErrorKind::SslEngineNotfound,
                format_args!("Failed to load base"),
            ));
        };
        crypto.base = Some(base);
        Ok(crypto)
    }

    /// Make the engine, if one was selected, the default for every
    /// algorithm (`ossl_set_engine_default`), 54 if it cannot be.
    pub(crate) fn set_default(&self, io: &mut TlsIo<'_>) -> Result<(), ErrorKind> {
        let Some(engine) = self.engine else {
            return Ok(());
        };
        let e = engine.as_ptr();
        // SAFETY: the engine; its id is its own C string.
        let id = unsafe { ENGINE_get_id(e) };
        // SAFETY: as above.
        let id = unsafe { core::ffi::CStr::from_ptr(id) }.to_bytes();
        // SAFETY: the engine, started.
        if unsafe { ENGINE_set_default(e, ENGINE_METHOD_ALL) } > 0 {
            io.info(format_args!("set default crypto engine '{}'", Text(id)));
            Ok(())
        } else {
            Err(io.fail(
                ErrorKind::SslEngineSetfailed,
                format_args!("set default crypto engine '{}' failed", Text(id)),
            ))
        }
    }

    /// A provider's library context is in use, whose store the multi
    /// must not keep past it (`USING_PROVIDER`).
    pub(crate) fn has_libctx(&self) -> bool {
        self.libctx.is_some()
    }

    /// A context of `method`, in the provider's library context if there
    /// is one, with its properties; null if it cannot be made.
    pub(crate) fn new_ctx(&self, method: *const SSL_METHOD) -> *mut SSL_CTX {
        match self.libctx {
            Some(libctx) => {
                let propq = self
                    .propq
                    .as_ref()
                    .map_or(ptr::null(), |p| p.as_ptr().cast());
                // SAFETY: the library context, alive as long as `self`,
                // which the session drops after the context; a C string
                // or null; the library's method.
                unsafe { SSL_CTX_new_ex(libctx.as_ptr(), propq, method) }
            }
            // SAFETY: the library's method.
            None => unsafe { openssl_sys::SSL_CTX_new(method) },
        }
    }
}

/// What a provider's store is asked for.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Wanted {
    Certificate,
    PrivateKey,
}

impl Crypto {
    /// The certificate or key at `uri` in the provider's store, made the
    /// context's (`providerload`, `providercheck`); its failure said as
    /// C says it. Only for a session whose provider is loaded.
    pub(crate) fn use_from_store(
        &self,
        ctx: NonNull<SSL_CTX>,
        uri: &[u8],
        wanted: Wanted,
        io: &mut TlsIo<'_>,
    ) -> Result<(), ErrorKind> {
        let libctx = self.libctx.expect("a provider loaded").as_ptr();
        let uri = c_string(uri)?;
        let fail = |io: &mut TlsIo<'_>, what: core::fmt::Arguments<'_>| {
            io.fail(ErrorKind::SslCertproblem, what)
        };
        // A certificate is fetched with no properties and no way to ask
        // for a password; a key with the provider's properties and
        // OpenSSL's own console (C's method defers to it, with no
        // password to give: `ui_data` is NULL).
        let (propq, ui, expect) = match wanted {
            Wanted::Certificate => (ptr::null(), ptr::null(), STORE_INFO_CERT),
            Wanted::PrivateKey => (
                self.propq
                    .as_ref()
                    .map_or(ptr::null(), |p| p.as_ptr().cast()),
                // SAFETY: the library's static method.
                unsafe { UI_OpenSSL() }.cast_const(),
                STORE_INFO_PKEY,
            ),
        };
        // SAFETY: a C string, the library context, a C string or null,
        // the library's method or null; the store is closed below.
        let store = unsafe {
            OSSL_STORE_open_ex(
                uri.as_ptr().cast(),
                libctx,
                propq,
                ui,
                ptr::null_mut(),
                ptr::null(),
                ptr::null(),
                ptr::null_mut(),
            )
        };
        if store.is_null() {
            let e = ErrText::last();
            return Err(fail(io, format_args!("Failed to open OpenSSL store: {e}")));
        }
        // SAFETY: the store.
        if unsafe { OSSL_STORE_expect(store, expect) } != 1 {
            let e = ErrText::last();
            fail(
                io,
                format_args!("Failed to set store preference. Ignoring the error: {e}"),
            );
        }
        // SAFETY: the store; the information, if any, is this one's to
        // free.
        let info = unsafe { OSSL_STORE_load(store) };
        let mut got: *mut c_void = ptr::null_mut();
        if !info.is_null() {
            // SAFETY: the information loaded.
            if unsafe { OSSL_STORE_INFO_get_type(info) } == expect {
                got = match wanted {
                    // SAFETY: as above, of that type; a reference that is
                    // this one's to free.
                    Wanted::Certificate => unsafe { OSSL_STORE_INFO_get1_CERT(info) }.cast(),
                    // SAFETY: as above.
                    Wanted::PrivateKey => unsafe { OSSL_STORE_INFO_get1_PKEY(info) }.cast(),
                };
            }
            // SAFETY: as above, freed once.
            unsafe { OSSL_STORE_INFO_free(info) };
        }
        // SAFETY: the store, closed once.
        unsafe { OSSL_STORE_close(store) };
        let c = ctx.as_ptr();
        match wanted {
            Wanted::Certificate => {
                if got.is_null() {
                    let e = ErrText::last();
                    return Err(fail(
                        io,
                        format_args!("No cert found in the openssl store: {e}"),
                    ));
                }
                // SAFETY: the context, which takes its own reference.
                let used = unsafe { openssl_sys::SSL_CTX_use_certificate(c, got.cast()) };
                // SAFETY: the reference taken above, given back once.
                unsafe { openssl_sys::X509_free(got.cast()) };
                if used != 1 {
                    let e = ErrText::last();
                    return Err(fail(
                        io,
                        format_args!("unable to set client certificate [{e}]"),
                    ));
                }
            }
            Wanted::PrivateKey => {
                if got.is_null() {
                    let e = ErrText::last();
                    return Err(fail(
                        io,
                        format_args!("No private key found in the openssl store: {e}"),
                    ));
                }
                // SAFETY: as above.
                let used = unsafe { openssl_sys::SSL_CTX_use_PrivateKey(c, got.cast()) };
                // SAFETY: as above.
                unsafe { openssl_sys::EVP_PKEY_free(got.cast()) };
                if used != 1 {
                    let e = ErrText::last();
                    return Err(fail(io, format_args!("unable to set private key [{e}]")));
                }
            }
        }
        Ok(())
    }
}

impl Drop for Crypto {
    fn drop(&mut self) {
        if let Some(e) = self.engine.take() {
            // SAFETY: the engine started, finished and given back once.
            unsafe { ENGINE_finish(e.as_ptr()) };
            // SAFETY: as above.
            unsafe { ENGINE_free(e.as_ptr()) };
        }
        for p in [self.base.take(), self.provider.take()]
            .into_iter()
            .flatten()
        {
            // SAFETY: a provider loaded, unloaded once.
            unsafe { openssl_sys::OSSL_PROVIDER_unload(p.as_ptr()) };
        }
        if let Some(l) = self.libctx.take() {
            // SAFETY: the library context, its providers unloaded, freed
            // once, after every context made in it.
            unsafe { openssl_sys::OSSL_LIB_CTX_free(l.as_ptr()) };
        }
    }
}

/// The ids of the engines the library has loaded, as it lists them
/// (`ossl_engines_list`).
pub(crate) fn ids() -> Result<Vec<Vec<u8>>, OutOfMemory> {
    let mut ids = Vec::new();
    // SAFETY: the list is walked as `engine.h` says, each engine passed
    // on to `ENGINE_get_next`, which releases it, and its id read while
    // it is held.
    let mut engine = unsafe { ENGINE_get_first() };
    while !engine.is_null() {
        // SAFETY: as above; an engine's id is a C string it keeps.
        let id = unsafe { ENGINE_get_id(engine) };
        // SAFETY: as above.
        let id = unsafe { core::ffi::CStr::from_ptr(id) }.to_bytes();
        let mut owned = Vec::new();
        let copied = owned
            .try_extend_from_slice(id)
            .and_then(|()| ids.try_push(owned));
        if let Err(e) = copied {
            // SAFETY: the engine held, released once.
            unsafe { ENGINE_free(engine) };
            return Err(e);
        }
        // SAFETY: as above.
        engine = unsafe { ENGINE_get_next(engine) };
    }
    Ok(ids)
}
