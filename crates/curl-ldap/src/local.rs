//! LDAP from libldap as `lib/ldap.c` drives it: a session of the
//! library's own to the host and port (`ldap_init`), each call waiting
//! for its answer (`ldap_simple_bind_s`, `ldap_search_s`), and the entries
//! of the search's answer read in turn. The way C's build takes where
//! libldap has no `ldap_init_fd`, as macOS's LDAP.framework.

#![allow(unsafe_code)]
#![cfg_attr(test, allow(clippy::disallowed_methods, clippy::disallowed_macros))]

use core::ffi::{CStr, c_char, c_int, c_void};
use core::marker::PhantomData;
use core::ptr;
use std::time::Duration;

use curl_alloc::{OutOfMemory, TryVec as _};
use curl_core::ldap::{
    Attribute, Code, Entries, Local, LocalCalls, LocalSession, LocalUrl, NoName, OpenLdapSession,
    Opened, RequireCert, Search, UrlError, Version,
};

use crate::common::{self, CSearch, bytes, scope_number, terminated};
use crate::sys;

/// libldap, as `lib/ldap.c` drives it.
#[derive(Debug)]
pub struct Legacy;

/// The library each handle speaks LDAP with, this way.
pub static LEGACY: Legacy = Legacy;

/// The library's version, as `curl -V` names it (`Curl_ldap_version`):
/// its vendor's name and its number, Apple's marked so,
/// `OpenLDAP/2.4.28/Apple`.
pub fn version() -> &'static str {
    static WORDS: common::Words = common::Words::new();
    // SAFETY: a constant C defines.
    let apple = unsafe { sys::curl_ldap_apple } != 0;
    common::version(&WORDS, if apple { "/Apple" } else { "" }, "LDAP/1")
}

/// A parameter the library could not be given (`LDAP_PARAM_ERROR`).
const PARAM_ERROR: Code = Code(-9);

impl Local for Legacy {
    fn vendor(&self) -> (&'static str, i32) {
        // SAFETY: a C string C defines, which lives as the program does.
        let name = unsafe { CStr::from_ptr((&raw const sys::curl_ldap_vendor_name).cast()) };
        let name = name.to_str().expect("the library names itself in ASCII");
        // SAFETY: a constant C defines.
        (name, unsafe { sys::curl_ldap_vendor_version })
    }

    fn parse_url(&self, url: &LocalUrl<'_>) -> Result<Search, UrlError> {
        common::parse_url(url.text)
    }

    fn describe(&self, code: Code) -> &'static [u8] {
        common::describe(code)
    }

    /// The session is told to speak TLS by its options
    /// (`LDAP_OPT_X_TLS`, which the library's headers always have), after
    /// it is made.
    fn open(&self, host: &[u8], port: u16, _secured: bool) -> Result<LocalSession, Opened> {
        let host = match terminated(host) {
            Ok(Some(host)) => host,
            // A name with a NUL reaches no host.
            Ok(None) => return Err(Opened::Refused),
            Err(OutOfMemory) => return Err(Opened::OutOfMemory),
        };
        // SAFETY: a C string; the library copies it.
        let ld = unsafe { sys::ldap_init(host.as_ptr().cast::<c_char>(), c_int::from(port)) };
        if ld.is_null() {
            return Err(Opened::Refused);
        }
        // A box that cannot be made drops the session, which frees it.
        let session = Session { ld };
        match curl_alloc::try_box(session) {
            Ok(b) => Ok(LocalSession::OpenLdap(b)),
            Err(OutOfMemory) => Err(Opened::OutOfMemory),
        }
    }
}

/// A session the library made (`ldap_init`), unbound as it is dropped.
#[derive(Debug)]
struct Session {
    ld: *mut sys::LDAP,
}

// SAFETY: a session is the library's alone and reached only through
// `&mut self`, so by one thread at a time; libldap keeps no session in
// a thread's own storage.
unsafe impl Send for Session {}

impl Session {
    /// Set `option` to the number `value` (an `int *`), as C does: the
    /// library's answer.
    fn set_int(&mut self, option: c_int, value: c_int) -> c_int {
        // SAFETY: a live session, and a number the call reads.
        unsafe { sys::ldap_set_option(self.ld, option, (&raw const value).cast::<c_void>()) }
    }
}

/// An option's answer as a result.
fn checked(rc: c_int) -> Result<(), Code> {
    if rc == sys::LDAP_OPT_SUCCESS {
        Ok(())
    } else {
        Err(Code(rc))
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        // C does not look at what the unbind says: the session is freed
        // whatever it is.
        // SAFETY: a live session, freed once, never used after.
        unsafe { sys::ldap_unbind_s(self.ld) };
    }
}

impl OpenLdapSession for Session {
    fn set_network_timeout(&mut self, timeout: Duration) {
        assert_eq!(timeout.subsec_nanos(), 0, "whole seconds, as C's");
        let tv = sys::timeval {
            tv_sec: timeout.as_secs().try_into().expect("seconds fit"),
            tv_usec: 0,
        };
        // As C, the library's answer is not looked at: one that has no
        // such timeout connects as it would.
        // SAFETY: a live session, and a time the call copies.
        unsafe {
            sys::ldap_set_option(
                self.ld,
                sys::LDAP_OPT_NETWORK_TIMEOUT,
                (&raw const tv).cast::<c_void>(),
            )
        };
    }

    fn set_ca_file(&mut self, path: &[u8]) -> Result<(), Code> {
        let path = terminated(path)
            .map_err(|OutOfMemory| Code::NO_MEMORY)?
            .ok_or(PARAM_ERROR)?;
        // SAFETY: a live session, and a C string the library copies.
        let rc = unsafe {
            sys::ldap_set_option(
                self.ld,
                sys::LDAP_OPT_X_TLS_CACERTFILE,
                path.as_ptr().cast::<c_void>(),
            )
        };
        checked(rc)
    }

    fn set_require_cert(&mut self, require: RequireCert) -> Result<(), Code> {
        let v = match require {
            RequireCert::Never => sys::LDAP_OPT_X_TLS_NEVER,
            RequireCert::Demand => sys::LDAP_OPT_X_TLS_DEMAND,
        };
        checked(self.set_int(sys::LDAP_OPT_X_TLS_REQUIRE_CERT, v))
    }

    fn set_tls_hard(&mut self) -> Result<(), Code> {
        checked(self.set_int(sys::LDAP_OPT_X_TLS, sys::LDAP_OPT_X_TLS_HARD))
    }

    fn simple_bind(&mut self, user: Option<&[u8]>, password: Option<&[u8]>) -> Code {
        let z = |s: Option<&[u8]>| match s {
            None => Ok(None),
            Some(s) => match terminated(s) {
                Ok(Some(z)) => Ok(Some(z)),
                Ok(None) => Err(PARAM_ERROR),
                Err(OutOfMemory) => Err(Code::NO_MEMORY),
            },
        };
        let (user, password) = match (z(user), z(password)) {
            (Ok(u), Ok(p)) => (u, p),
            (Err(c), _) | (_, Err(c)) => return c,
        };
        let c = |z: &Option<Vec<u8>>| z.as_ref().map_or(ptr::null(), |z| z.as_ptr().cast());
        // SAFETY: a live session, and NULL or C strings the call reads.
        Code(unsafe { sys::ldap_simple_bind_s(self.ld, c(&user), c(&password)) })
    }
}

impl LocalCalls for Session {
    fn set_version(&mut self, version: Version) {
        let v = match version {
            Version::V2 => sys::LDAP_VERSION2,
            Version::V3 => sys::LDAP_VERSION3,
        };
        // As C, the answer is not looked at: a version not taken shows
        // in the bind's.
        self.set_int(sys::LDAP_OPT_PROTOCOL_VERSION, v);
    }

    fn set_no_referrals(&mut self) {
        // `LDAP_OPT_OFF`, a NULL pointer; as C, the answer is not looked at.
        // SAFETY: a live session; the option takes the pointer's value.
        unsafe { sys::ldap_set_option(self.ld, sys::LDAP_OPT_REFERRALS, ptr::null()) };
    }

    fn search(&mut self, search: &Search) -> Result<(Code, Box<dyn Entries + '_>), Code> {
        let mut c = CSearch::new(search)?;
        let mut res: *mut sys::LDAPMessage = ptr::null_mut();
        // SAFETY: a live session; NULL or C strings, and NULL or a
        // NULL-terminated list of them, which the library only reads;
        // where the answer goes.
        let rc = unsafe {
            sys::ldap_search_s(
                self.ld,
                c.dn(),
                scope_number(search.scope),
                c.filter(),
                c.attrs(),
                0,
                &raw mut res,
            )
        };
        let found = Found {
            ld: self.ld,
            res,
            entry: ptr::null_mut(),
            started: false,
            ber: ptr::null_mut(),
            attrs_started: false,
            dn: ptr::null_mut(),
            attr: ptr::null_mut(),
            vals: ptr::null_mut(),
            session: PhantomData,
        };
        let code = Code(rc);
        if code != Code::SUCCESS && code != Code::SIZELIMIT_EXCEEDED {
            // What was found, if anything, is freed with `found`.
            return Err(code);
        }
        match curl_alloc::try_box(found) {
            Ok(b) => {
                let b: Box<dyn Entries + '_> = b;
                Ok((code, b))
            }
            Err(OutOfMemory) => Err(Code::NO_MEMORY),
        }
    }
}

/// A search's answer, its entries read in turn, each the library's until
/// the next is read, and the whole freed as it is dropped.
struct Found<'s> {
    ld: *mut sys::LDAP,
    /// The answer, NULL for none.
    res: *mut sys::LDAPMessage,
    /// The entry read, NULL before the first and after the last.
    entry: *mut sys::LDAPMessage,
    started: bool,
    /// Where the library is in the entry's attributes.
    ber: *mut sys::BerElement,
    attrs_started: bool,
    /// The entry's name, as last read.
    dn: *mut c_char,
    /// The attribute read, and its values.
    attr: *mut c_char,
    vals: *mut *mut sys::berval,
    session: PhantomData<&'s mut Session>,
}

impl Found<'_> {
    /// Free the attribute read and its values.
    fn free_attribute(&mut self) {
        if !self.vals.is_null() {
            // SAFETY: the library's values, freed once.
            unsafe { sys::ldap_value_free_len(self.vals) };
            self.vals = ptr::null_mut();
        }
        if !self.attr.is_null() {
            // SAFETY: the library's string, freed once.
            unsafe { sys::ldap_memfree(self.attr.cast::<c_void>()) };
            self.attr = ptr::null_mut();
        }
    }

    /// Free what was read of the entry.
    fn free_entry(&mut self) {
        self.free_attribute();
        if !self.dn.is_null() {
            // SAFETY: the library's string, freed once.
            unsafe { sys::ldap_memfree(self.dn.cast::<c_void>()) };
            self.dn = ptr::null_mut();
        }
        if !self.ber.is_null() {
            // SAFETY: the library's place in the attributes, freed once,
            // its buffer the entry's (`ber_free(ber, 0)`, as C).
            unsafe { sys::ber_free(self.ber, 0) };
            self.ber = ptr::null_mut();
        }
        self.attrs_started = false;
    }
}

impl Drop for Found<'_> {
    fn drop(&mut self) {
        self.free_entry();
        if !self.res.is_null() {
            // SAFETY: the library's answer, freed once, no entry of it
            // used after.
            unsafe { sys::ldap_msgfree(self.res) };
        }
    }
}

impl Entries for Found<'_> {
    fn next_entry(&mut self) -> bool {
        self.free_entry();
        if self.res.is_null() {
            return false;
        }
        self.entry = if self.started {
            if self.entry.is_null() {
                return false;
            }
            // SAFETY: a live session, and an entry of its answer.
            unsafe { sys::ldap_next_entry(self.ld, self.entry) }
        } else {
            self.started = true;
            // SAFETY: a live session, and its answer.
            unsafe { sys::ldap_first_entry(self.ld, self.res) }
        };
        !self.entry.is_null()
    }

    fn dn(&mut self) -> Result<&[u8], NoName> {
        assert!(!self.entry.is_null(), "an entry is read");
        if !self.dn.is_null() {
            // SAFETY: the library's string, freed once.
            unsafe { sys::ldap_memfree(self.dn.cast::<c_void>()) };
        }
        // SAFETY: a live session, and an entry of its answer.
        self.dn = unsafe { sys::ldap_get_dn(self.ld, self.entry) };
        if self.dn.is_null() {
            return Err(NoName::Missing);
        }
        // SAFETY: the library's C string, freed only as `self` reads
        // another or is dropped, which `&mut self` keeps from happening
        // while the bytes are borrowed.
        Ok(unsafe { CStr::from_ptr(self.dn) }.to_bytes())
    }

    fn next_attribute(&mut self) -> Result<Option<Attribute<'_>>, OutOfMemory> {
        assert!(!self.entry.is_null(), "an entry is read");
        self.free_attribute();
        self.attr = if self.attrs_started {
            if self.ber.is_null() {
                return Ok(None);
            }
            // SAFETY: a live session, an entry of its answer, and the
            // place the first call left in its attributes.
            unsafe { sys::ldap_next_attribute(self.ld, self.entry, self.ber) }
        } else {
            self.attrs_started = true;
            // SAFETY: a live session, an entry of its answer, and where
            // the place in its attributes goes.
            unsafe { sys::ldap_first_attribute(self.ld, self.entry, &raw mut self.ber) }
        };
        if self.attr.is_null() {
            return Ok(None);
        }
        // SAFETY: a live session, an entry of its answer, and the C
        // string of one of its attributes.
        self.vals = unsafe { sys::ldap_get_values_len(self.ld, self.entry, self.attr) };
        let values = if self.vals.is_null() {
            None
        } else {
            let mut all = Vec::new();
            for i in 0.. {
                // SAFETY: a NULL-terminated list, read up to its NULL: `i`
                // is at most its NULL's place.
                let at = unsafe { self.vals.add(i) };
                // SAFETY: an element of the list, as above.
                let bv = unsafe { at.read() };
                if bv.is_null() {
                    break;
                }
                // SAFETY: not NULL, one of the library's values.
                let bv = unsafe { &*bv };
                // SAFETY: one of the library's values, freed only as
                // `self` reads another attribute or is dropped, which the
                // borrow of `self` keeps from happening.
                let value = unsafe { bytes(bv) }.unwrap_or_default();
                all.try_push(value)?;
            }
            Some(all)
        };
        // SAFETY: the library's C string, freed as the values are.
        let name = unsafe { CStr::from_ptr(self.attr) }.to_bytes();
        Ok(Some(Attribute { name, values }))
    }
}

#[cfg(test)]
#[path = "local_tests.rs"]
mod tests;
