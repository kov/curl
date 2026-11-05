//! LDAP and LDAPS for the curl rewrite, driven the way C's build drives
//! its library: libldap over the connection's socket where it has
//! `ldap_init_fd` (`lib/openldap.c`, `USE_OPENLDAP`), over a connection
//! of its own where it has not (`lib/ldap.c`), as macOS's LDAP.framework,
//! an OpenLDAP 2.4; and on Windows WinLDAP, over a connection of its own,
//! as `lib/ldap.c` drives it there (`USE_WIN32_LDAP`).

#[cfg(all(test, any(ldap, windows)))]
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
#[cfg(any(ldap, windows))]
mod strings;
#[cfg(ldap)]
mod sys;
#[cfg(windows)]
mod win;

use curl_core::ldap::LdapLibrary;

/// The library each handle speaks LDAP with, and the way it is driven,
/// if the build has one.
pub const fn library() -> Option<LdapLibrary> {
    #[cfg(windows)]
    return Some(LdapLibrary::Local(&win::WINLDAP));
    #[cfg(openldap)]
    return Some(LdapLibrary::Fd(&openldap::LIBLDAP));
    #[cfg(all(ldap, not(openldap)))]
    return Some(LdapLibrary::Local(&local::LEGACY));
    #[cfg(not(any(ldap, windows)))]
    return None;
}

/// The library's version, as `curl -V` names it (`Curl_ldap_version`),
/// if the build has one.
pub fn version() -> Option<&'static str> {
    #[cfg(windows)]
    return Some(win::version());
    #[cfg(openldap)]
    return Some(openldap::version());
    #[cfg(all(ldap, not(openldap)))]
    return Some(local::version());
    #[cfg(not(any(ldap, windows)))]
    return None;
}
