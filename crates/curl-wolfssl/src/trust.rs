//! The certificates a session trusts, loaded into its context's store as
//! the peer's first bytes are about to be read (`wssl_populate_x509_store`),
//! and that store kept for the multi's next connections
//! (`Curl_wssl_setup_x509_store`, `wssl_get_cached_x509_store`,
//! `wssl_set_cached_x509_store`), which take it in place of loading their
//! own.

use curl_alloc::TryArc;
use curl_core::error::ErrorKind;
use curl_core::options::CaCache;
use curl_core::tls::{StoreCache, Text, TlsCx, TlsIdentity, TlsShared};

use crate::library::{Ctx, Store as _, Wolfssl, as_c, c_string};

/// What this library keeps for a multi: the store its connections last
/// loaded.
type Kept<S> = StoreCache<S>;

/// A session's store may be taken from the multi, and kept there
/// (`cache_criteria_met`): the certificates to trust come from a file
/// alone, or from the library's default.
pub(crate) fn cacheable(identity: &TlsIdentity) -> bool {
    let o = &identity.options;
    o.ca_cache != CaCache::Off
        && identity.verify_peer
        && identity.ca_path().is_none()
        && identity.ca_blob().is_none()
        && o.crl_file.is_none()
        && !identity.native_ca_store()
}

/// A store loaded for `kept` serves `wanted`: they name the same CA file
/// (`wssl_cached_x509_store_different`).
fn same(kept: &TlsIdentity, wanted: &TlsIdentity) -> bool {
    kept.ca_file() == wanted.ca_file()
}

/// What the multi's kept store is to the context.
enum Found<S> {
    /// It is the context's already.
    InUse,
    /// Another reference to it, for the context.
    Take(S),
    /// None serves.
    None,
}

/// Set the trust store of `ctx` up for a session with `identity`
/// (`Curl_wssl_setup_x509_store`): the store `shared` keeps for the
/// multi, if one serves it; else, where the multi may keep one, a store
/// of the context's own made, loaded and kept; else the context's store
/// loaded.
pub(crate) fn setup<W: Wolfssl>(
    lib: &W,
    ctx: &mut W::Ctx,
    identity: &TryArc<TlsIdentity>,
    shared: Option<&TlsShared>,
    io: &mut TlsCx<'_>,
) -> Result<(), ErrorKind> {
    let criteria = cacheable(identity);
    let now = io.now();
    let found = match shared.filter(|_| criteria) {
        Some(shared) => shared
            .with(Kept::<W::Store>::default, |kept| {
                match kept.get(identity, now, same) {
                    Some(store) if ctx.uses_store(store) => Found::InUse,
                    Some(store) => store.another().map_or(Found::None, Found::Take),
                    None => Found::None,
                }
            })
            .ok()
            .flatten()
            .unwrap_or(Found::None),
        None => Found::None,
    };
    match found {
        Found::InUse => Ok(()),
        Found::Take(store) => {
            ctx.set_store(store);
            Ok(())
        }
        Found::None if criteria => {
            // The context's first store is not one to share: one of its
            // own is made for the multi (curl/curl#14278).
            let Some(store) = lib.new_store() else {
                return Err(io.fail(
                    ErrorKind::OutOfMemory,
                    format_args!("SSL: could not create a X509 store"),
                ));
            };
            ctx.set_store(store);
            populate(ctx, identity, io)?;
            if let (Some(shared), Some(store)) = (shared, ctx.store()) {
                // Not kept out of memory, as C goes on without it.
                let (Ok(Some(()) | None) | Err(_)) =
                    shared.with(Kept::<W::Store>::default, |kept| {
                        kept.set(identity, now, store);
                    });
            }
            Ok(())
        }
        Found::None => populate(ctx, identity, io),
    }
}

/// Load what the session trusts into the context's store
/// (`wssl_populate_x509_store`): the system's, a blob, and the file (but
/// for a blob) and directory, which fail the session only where it
/// verifies its peer and nothing else loaded.
fn populate<C: Ctx>(
    ctx: &mut C,
    identity: &TlsIdentity,
    io: &mut TlsCx<'_>,
) -> Result<(), ErrorKind> {
    let mut native = false;
    if identity.native_ca_store() {
        if ctx.system_ca() {
            native = true;
            io.info(format_args!("successfully imported native CA store"));
        } else {
            io.info(format_args!(
                "error importing native CA store, continuing anyway"
            ));
        }
    }
    let blob = identity.ca_blob();
    if let Some(blob) = blob {
        if !ctx.ca_buffer(blob) {
            return Err(io.fail(
                ErrorKind::SslCacertBadfile,
                format_args!("error importing CA certificate blob"),
            ));
        }
        io.info(format_args!("successfully imported CA certificate blob"));
    }
    // A blob takes the file's place.
    let file = if blob.is_some() {
        None
    } else {
        identity.ca_file()
    };
    let path = identity.ca_path();
    let none = b"none".as_slice();
    io.trace(format_args!(
        "wssl_populate_x509_store, path={}, blob={}",
        Text(file.unwrap_or(none)),
        u8::from(blob.is_some())
    ));
    if file.is_none() && path.is_none() {
        return Ok(());
    }
    let c_file = file.map(c_string).transpose()?;
    let c_path = path.map(c_string).transpose()?;
    let loaded = ctx.ca_locations(c_file.as_deref().map(as_c), c_path.as_deref().map(as_c));
    let (file, path) = (Text(file.unwrap_or(none)), Text(path.unwrap_or(none)));
    if loaded {
        io.info(format_args!(
            "successfully set certificate verify locations:"
        ));
    } else if identity.verify_peer && !native && blob.is_none() {
        return Err(io.fail(
            ErrorKind::SslCacertBadfile,
            format_args!(
                "error setting certificate verify locations: CAfile: {file} CApath: {path}"
            ),
        ));
    } else {
        io.info(format_args!(
            "error setting certificate verify locations, continuing anyway:"
        ));
    }
    io.info(format_args!(" CAfile: {file}"));
    io.info(format_args!(" CApath: {path}"));
    Ok(())
}
