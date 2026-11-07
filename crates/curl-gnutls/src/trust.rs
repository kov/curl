//! The anchors a session trusts, and the revocation lists it checks
//! (`gtls_populate_creds`), loaded into its certificate credentials as
//! the peer's first bytes are about to be read; and those credentials
//! kept for the multi's next connections (`Curl_gtls_client_trust_setup`,
//! `gtls_get_cached_creds`, `gtls_set_cached_creds`), which take them in
//! place of loading their own.

use curl_alloc::{OutOfMemory, TryArc};
use curl_core::error::ErrorKind;
use curl_core::options::CaCache;
use curl_core::time::Instant;
use curl_core::tls::{StoreCache, TlsCx, TlsIdentity, TlsShared};

use crate::library::{Creds as _, Gnutls, Rc, as_c, c_string, strerror};
use curl_core::tls::Text;

/// The credentials a multi keeps for its next connections, with the
/// settings they were loaded for and when they were made
/// (`gtls_shared_creds`).
type Kept<C> = StoreCache<TryArc<C>>;

/// A session's credentials may be taken from the multi, and kept there
/// (`cache_criteria_met`): the anchors come from a file alone, or from
/// the library's default, and the credentials hold no client
/// certificate, which GnuTLS adds to them.
pub(crate) fn cacheable(identity: &TlsIdentity) -> bool {
    let o = &identity.options;
    o.ca_cache != CaCache::Off
        && identity.verify_peer
        && identity.ca_path().is_none()
        && identity.ca_blob().is_none()
        && o.crl_file.is_none()
        && !identity.native_ca_store()
        && o.cert.is_none()
}

/// Credentials loaded for `kept` serve `wanted`: they name the same CA
/// file (`gtls_shared_creds_different`).
fn same(kept: &TlsIdentity, wanted: &TlsIdentity) -> bool {
    kept.ca_file() == wanted.ca_file()
}

/// Set the trust up for a session holding `creds`, made at `made`
/// (`Curl_gtls_client_trust_setup`): the multi's credentials taken in
/// place of its own, `set` pointing the session at them, if they may be
/// and are good for it; else its own loaded, and kept for the multi if
/// they may be.
pub(crate) fn setup<G: Gnutls>(
    lib: &G,
    identity: &TryArc<TlsIdentity>,
    shared: Option<&TlsShared>,
    creds: &mut TryArc<G::Creds>,
    made: Instant,
    io: &mut TlsCx<'_>,
    set: &mut dyn FnMut(&G::Creds) -> Rc,
) -> Result<(), ErrorKind> {
    let criteria = cacheable(identity);
    let cached = if criteria {
        shared.and_then(|s| taken::<G::Creds>(s, identity, io.now()))
    } else {
        None
    };
    if let Some(cached) = cached {
        io.trace(format_args!("using shared trust anchors and CRLs"));
        let rc = set(&cached);
        // The session points at them before its own go.
        *creds = cached;
        if rc != 0 {
            return Err(io.fail(
                ErrorKind::SslConnectError,
                format_args!("gnutls_credentials_set() failed: {}", strerror(lib, rc)),
            ));
        }
        return Ok(());
    }
    io.trace(format_args!("loading trust anchors and CRLs"));
    populate(lib, identity, creds, io)?;
    if criteria && let Some(shared) = shared {
        // Out of memory, they are not kept, as C goes on without.
        let _ = keep(shared, identity, creds, made);
    }
    Ok(())
}

/// The multi's credentials, if they are good for `identity` at `now`
/// (`gtls_get_cached_creds`).
fn taken<C: 'static + Send + Sync>(
    shared: &TlsShared,
    identity: &TlsIdentity,
    now: Instant,
) -> Option<TryArc<C>> {
    shared
        .with(Kept::<C>::default, |kept| {
            kept.get(identity, now, same).cloned()
        })
        .ok()
        .flatten()
        .flatten()
}

/// Keep `creds`, the session's own just loaded at `made`, for the multi,
/// in place of any it kept (`gtls_set_cached_creds`).
fn keep<C: 'static + Send + Sync>(
    shared: &TlsShared,
    identity: &TryArc<TlsIdentity>,
    creds: &TryArc<C>,
    made: Instant,
) -> Result<(), OutOfMemory> {
    let creds = creds.clone();
    shared.with(Kept::<C>::default, |kept| kept.set(identity, made, creds))?;
    Ok(())
}

/// Load what the session trusts into `creds` (`gtls_populate_creds`),
/// which it alone holds.
pub(crate) fn populate<G: Gnutls>(
    lib: &G,
    identity: &TlsIdentity,
    creds: &TryArc<G::Creds>,
    io: &mut TlsCx<'_>,
) -> Result<(), ErrorKind> {
    assert_eq!(
        TryArc::count(creds),
        1,
        "credentials are changed only while one session holds them"
    );
    if !identity.verify_peer {
        io.info(format_args!("SSL Trust: peer verification disabled"));
        return Ok(());
    }
    let mut empty = true;
    io.info(format_args!("SSL Trust Anchors:"));
    if identity.native_ca_store() {
        let rc = creds.system_trust();
        if rc < 0 {
            io.info(format_args!(
                "error reading native CA store ({}), continuing anyway",
                strerror(lib, rc)
            ));
        } else {
            io.info(format_args!(
                "  Native: {rc} certificates from system trust"
            ));
            if rc > 0 {
                empty = false;
            }
        }
    }
    if let Some(blob) = identity.ca_blob() {
        if u32::try_from(blob.len()).is_err() {
            return Err(io.fail(
                ErrorKind::SslCacertBadfile,
                format_args!("certificate blob too long: {} bytes", blob.len()),
            ));
        }
        let rc = creds.trust_mem(blob);
        empty = empty && rc <= 0;
        if rc < 0 {
            io.info(format_args!(
                "error reading CA cert blob ({}){}",
                strerror(lib, rc),
                anyway(empty)
            ));
            if empty {
                io.verified(rc);
                return Err(ErrorKind::SslCacertBadfile);
            }
        } else {
            io.info(format_args!("  CA Blob: {rc} certificates"));
        }
    } else if let Some(file) = identity.ca_file() {
        let name = c_string(file)?;
        creds.allow_v1_ca();
        let rc = creds.trust_file(as_c(&name));
        empty = empty && rc <= 0;
        if rc < 0 {
            io.info(format_args!(
                "error reading CA cert file {} ({}){}",
                Text(file),
                strerror(lib, rc),
                anyway(empty)
            ));
            if empty {
                io.verified(rc);
                return Err(ErrorKind::SslCacertBadfile);
            }
        } else {
            io.info(format_args!(
                "  CAfile: {rc} certificates in {}",
                Text(file)
            ));
        }
    }
    if let Some(dir) = identity.ca_path() {
        let name = c_string(dir)?;
        let rc = creds.trust_dir(as_c(&name));
        empty = empty && rc <= 0;
        if rc < 0 {
            io.info(format_args!(
                "error reading CA cert file {} ({}){}",
                Text(dir),
                strerror(lib, rc),
                anyway(empty)
            ));
            if empty {
                io.verified(rc);
                return Err(ErrorKind::SslCacertBadfile);
            }
        } else {
            io.info(format_args!("  CApath: {rc} certificates in {}", Text(dir)));
        }
    }
    if empty {
        io.info(format_args!("  no trust anchors configured"));
    }
    if let Some(crl) = identity.options.crl_file.as_deref() {
        let name = c_string(crl)?;
        let rc = creds.crl_file(as_c(&name));
        if rc < 0 {
            return Err(io.fail(
                ErrorKind::SslCrlBadfile,
                format_args!(
                    "error reading CRL file {} ({})",
                    Text(crl),
                    strerror(lib, rc)
                ),
            ));
        }
        io.info(format_args!("  CRLfile: {rc} CRL in {}", Text(crl)));
    }
    Ok(())
}

/// What a failed source adds when another gave anchors.
fn anyway(empty: bool) -> &'static str {
    if empty { "" } else { ", continuing anyway" }
}
