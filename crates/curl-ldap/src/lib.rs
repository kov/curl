//! LDAP and LDAPS for the curl rewrite, from libldap, driven the way C's
//! build drives it: over the connection's socket where libldap has
//! `ldap_init_fd` (`lib/openldap.c`, `USE_OPENLDAP`), over a connection
//! of its own where it has not (`lib/ldap.c`), as macOS's LDAP.framework,
//! an OpenLDAP 2.4. Windows' C build takes `lib/ldap.c` over WinLDAP,
//! which is not bound yet: such a build has no LDAP library, as a C build
//! without one.

#[cfg(all(test, ldap))]
mod ber;
#[cfg(ldap)]
mod common;
// Built wherever libldap links, so its binding is tested on every
// build; where `ldap_init_fd` is there, only its tests use it.
#[cfg(ldap)]
#[cfg_attr(openldap, allow(dead_code))]
mod local;
#[cfg(openldap)]
mod openldap;
#[cfg(ldap)]
mod sys;

use curl_core::ldap::LdapLibrary;

/// The library each handle speaks LDAP with, and the way it is driven,
/// if the build has one.
pub const fn library() -> Option<LdapLibrary> {
    #[cfg(openldap)]
    return Some(LdapLibrary::Fd(&openldap::LIBLDAP));
    #[cfg(all(ldap, not(openldap)))]
    return Some(LdapLibrary::Local(&local::LEGACY));
    #[cfg(not(ldap))]
    return None;
}

/// The library's version, as `curl -V` names it (`Curl_ldap_version`),
/// if the build has one.
pub fn version() -> Option<&'static str> {
    #[cfg(openldap)]
    return Some(openldap::version());
    #[cfg(all(ldap, not(openldap)))]
    return Some(local::version());
    #[cfg(not(ldap))]
    return None;
}
