//! LDAP and LDAPS for the curl rewrite.
//!
//! From OpenLDAP's libldap where it has `ldap_init_fd`, as C's build
//! takes `lib/openldap.c` only then (`USE_OPENLDAP`, `HAVE_LDAP_INIT_FD`).
//! Elsewhere, as on macOS, whose LDAP.framework is an OpenLDAP 2.4
//! without it, C's build takes `lib/ldap.c`, the backend it also takes
//! over WinLDAP; that backend is not ported yet, so such a build has no
//! LDAP library, as a C build without one.

#[cfg(openldap)]
mod openldap;

use curl_core::ldap::Ldap;

/// The library each handle speaks LDAP with, if the build has one.
pub const fn library() -> Option<&'static dyn Ldap> {
    #[cfg(openldap)]
    return Some(&openldap::LIBLDAP);
    #[cfg(not(openldap))]
    return None;
}

/// The library's version, as `curl -V` names it (`Curl_ldap_version`),
/// if the build has one.
pub fn version() -> Option<&'static str> {
    #[cfg(openldap)]
    return Some(openldap::version());
    #[cfg(not(openldap))]
    return None;
}
