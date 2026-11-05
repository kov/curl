//! LDAP from WinLDAP (`wldap32`) as `lib/ldap.c` drives it with
//! `USE_WIN32_LDAP`: a session of the library's own to the host and port
//! (`ldap_init`, `ldap_sslinit` for `ldaps:`), each call waiting for its
//! answer, binds made as `ldap_win_bind` makes them, simply or by SSPI,
//! and the entries of the search's answer read in turn. The URL is read
//! by C's own parser, as WinLDAP has none. The calls are the ANSI ones a
//! build without `UNICODE` makes, handed the bytes as they are.

#![allow(unsafe_code)]
#![cfg_attr(test, allow(clippy::disallowed_methods, clippy::disallowed_macros))]

use core::ffi::{CStr, c_char, c_void};
use core::marker::PhantomData;
use core::ptr;

use curl_alloc::{OutOfMemory, TryVec as _};
use curl_core::ldap::{
    Attribute, Code, Entries, Local, LocalCalls, LocalSession, LocalUrl, LowUrlError, NoName,
    Opened, Scope, Search, SspiMethod, UrlError, Version, WinBind, WinLdapSession, parse_url_low,
};
use windows_sys::Win32::Networking::Ldap as sys;
use windows_sys::Win32::Security::Authentication::Identity::{
    SEC_WINNT_AUTH_IDENTITY_EXA, SEC_WINNT_AUTH_IDENTITY_VERSION,
};
use windows_sys::Win32::Security::Cryptography::{CERT_CONTEXT, CertFreeCertificateContext};

use crate::strings::{c_list, terminated};

/// WinLDAP, as `lib/ldap.c` drives it.
#[derive(Debug)]
pub struct WinLdap;

/// The library each handle speaks LDAP with.
pub static WINLDAP: WinLdap = WinLdap;

/// The library as `curl -V` names it (`Curl_ldap_version`).
pub fn version() -> &'static str {
    "WinLDAP"
}

/// `LDAP_VENDOR_NAME` and `LDAP_VENDOR_VERSION` (`winldap.h`).
const VENDOR: (&str, i32) = ("Microsoft Corporation.", 510);

/// The library's codes for running out of memory and for a parameter it
/// cannot take (`LDAP_NO_MEMORY`, `LDAP_PARAM_ERROR`).
const NO_MEMORY: Code = Code(sys::LDAP_NO_MEMORY);
const PARAM_ERROR: Code = Code(sys::LDAP_PARAM_ERROR);

/// The SSPI methods a bind is made with (`LDAP_AUTH_NEGOTIATE`,
/// `LDAP_AUTH_DIGEST`: `LDAP_AUTH_OTHERKIND` with a bit of their own).
const AUTH_NEGOTIATE: u32 = sys::LDAP_AUTH_OTHERKIND as u32 | 0x0400;
const AUTH_DIGEST: u32 = sys::LDAP_AUTH_OTHERKIND as u32 | 0x4000;

/// An identity's strings are in the ANSI code page
/// (`SEC_WINNT_AUTH_IDENTITY_ANSI`), as a build without `UNICODE` has
/// them.
const IDENTITY_ANSI: u32 = 1;

/// `LDAP_OPT_ON`, an option's value as a pointer.
const OPT_ON: *const c_void = ptr::without_provenance(1);

impl Local for WinLdap {
    fn vendor(&self) -> (&'static str, i32) {
        VENDOR
    }

    /// C's own parser, its errors in the library's codes.
    fn parse_url(&self, url: &LocalUrl<'_>) -> Result<Search, UrlError> {
        parse_url_low(url.path, url.query).map_err(|e| match e {
            LowUrlError::InvalidSyntax => UrlError(sys::LDAP_INVALID_SYNTAX),
            LowUrlError::NoMemory => UrlError(sys::LDAP_NO_MEMORY),
        })
    }

    fn describe(&self, code: Code) -> &'static [u8] {
        // The library's words for a code it has none for are none.
        let Ok(n) = u32::try_from(code.0) else {
            return b"";
        };
        // SAFETY: any number; the library's static words for it, the
        // ANSI ones as C's build asks for whatever its `UNICODE`.
        let s = unsafe { sys::ldap_err2stringA(n) };
        if s.is_null() {
            return b"";
        }
        // SAFETY: a C string of the library's, which lives as it is
        // loaded, as long as the process.
        unsafe { CStr::from_ptr(s.cast::<c_char>()) }.to_bytes()
    }

    fn open(&self, host: &[u8], port: u16, secured: bool) -> Result<LocalSession, Opened> {
        let host = match terminated(host) {
            Ok(Some(host)) => host,
            // A name with a NUL reaches no host.
            Ok(None) => return Err(Opened::Refused),
            Err(OutOfMemory) => return Err(Opened::OutOfMemory),
        };
        let ld = if secured {
            // SAFETY: a C string the library copies; a port; TLS on.
            unsafe { sys::ldap_sslinitA(host.as_ptr(), u32::from(port), 1) }
        } else {
            // SAFETY: a C string the library copies, and a port.
            unsafe { sys::ldap_initA(host.as_ptr(), u32::from(port)) }
        };
        if ld.is_null() {
            return Err(Opened::Refused);
        }
        // A box that cannot be made drops the session, which frees it.
        let session = Session { ld };
        match curl_alloc::try_box(session) {
            Ok(b) => Ok(LocalSession::Windows(b)),
            Err(OutOfMemory) => Err(Opened::OutOfMemory),
        }
    }
}

/// A session the library made, unbound as it is dropped.
#[derive(Debug)]
struct Session {
    ld: *mut sys::LDAP,
}

// SAFETY: a session is the library's alone and reached only through
// `&mut self`, so by one thread at a time; WinLDAP's sessions may be used
// from any thread.
unsafe impl Send for Session {}

impl Session {
    /// Set `option` to what `value` points at, or is, as the option
    /// takes it, the library's answer not looked at, as C does not.
    fn set(&mut self, option: u32, value: *const c_void) {
        let option = i32::try_from(option).expect("the library's options are small");
        // SAFETY: a live session; what the option reads, which lives
        // across the call.
        unsafe { sys::ldap_set_option(self.ld, option, value) };
    }
}

/// The peer's certificate accepted, whatever it is, and freed, as the
/// library leaves it to the callback (`bypass_cert_verify`).
unsafe extern "system" fn bypass_cert_verify(
    _: *mut sys::LDAP,
    cert: *mut *mut CERT_CONTEXT,
) -> bool {
    // SAFETY: the library hands a pointer to the certificate it made.
    let made = unsafe { *cert };
    // SAFETY: the certificate, the callback's to free, freed once.
    unsafe { CertFreeCertificateContext(made) };
    true
}

impl LocalCalls for Session {
    fn set_version(&mut self, version: Version) {
        let v: i32 = match version {
            Version::V2 => sys::LDAP_VERSION2 as i32,
            Version::V3 => sys::LDAP_VERSION3 as i32,
        };
        self.set(sys::LDAP_OPT_PROTOCOL_VERSION, (&raw const v).cast());
    }

    fn set_no_referrals(&mut self) {
        // `LDAP_OPT_OFF`, a NULL pointer.
        self.set(sys::LDAP_OPT_REFERRALS, ptr::null());
    }

    fn search(&mut self, search: &Search) -> Result<(Code, Box<dyn Entries + '_>), Code> {
        let dn = search.dn.as_deref().map(c_string).transpose()?;
        let filter = search.filter.as_deref().map(c_string).transpose()?;
        let mut attrs = Vec::new();
        for a in search.attrs.iter().flatten() {
            attrs
                .try_push(c_string(a)?)
                .map_err(|OutOfMemory| NO_MEMORY)?;
        }
        let list = match search.attrs {
            Some(_) => Some(c_list(&attrs).map_err(|OutOfMemory| NO_MEMORY)?),
            None => None,
        };
        let c = |z: &Option<Vec<u8>>| z.as_ref().map_or(ptr::null(), |z| z.as_ptr());
        let scope = match search.scope {
            Scope::Base => sys::LDAP_SCOPE_BASE,
            Scope::OneLevel => sys::LDAP_SCOPE_ONELEVEL,
            Scope::Subtree => sys::LDAP_SCOPE_SUBTREE,
            Scope::Subordinate => unreachable!("C's parser reads no such scope"),
        };
        let list_ptr = list
            .as_ref()
            .map_or(ptr::null(), |l| l.as_ptr().cast::<*const i8>());
        let mut res: *mut sys::LDAPMessage = ptr::null_mut();
        // SAFETY: a live session; NULL or C strings, and NULL or a
        // NULL-terminated list of them, which live across the call and
        // which the library only reads; where the answer goes.
        let rc = unsafe {
            sys::ldap_search_sA(
                self.ld,
                c(&dn),
                scope,
                c(&filter),
                list_ptr,
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
        let code = Code(rc as i32);
        if code != Code::SUCCESS && code.0 != sys::LDAP_SIZELIMIT_EXCEEDED {
            // What was found, if anything, is freed with `found`.
            return Err(code);
        }
        match curl_alloc::try_box(found) {
            Ok(b) => {
                let b: Box<dyn Entries + '_> = b;
                Ok((code, b))
            }
            Err(OutOfMemory) => Err(NO_MEMORY),
        }
    }
}

impl WinLdapSession for Session {
    fn set_ssl(&mut self) {
        self.set(sys::LDAP_OPT_SSL, OPT_ON);
    }

    fn accept_any_cert(&mut self) {
        let callback: unsafe extern "system" fn(*mut sys::LDAP, *mut *mut CERT_CONTEXT) -> bool =
            bypass_cert_verify;
        // The option takes the callback itself, as C hands it.
        self.set(sys::LDAP_OPT_SERVER_CERTIFICATE, callback as *const c_void);
    }

    fn bind(&mut self, how: WinBind<'_>) -> Code {
        match how {
            WinBind::Simple { user, password } => self.simple_bind(user, password),
            WinBind::Sspi {
                method,
                user,
                password,
            } => {
                let method = match method {
                    SspiMethod::Negotiate => AUTH_NEGOTIATE,
                    SspiMethod::Digest => AUTH_DIGEST,
                };
                let Ok(mut identity) = Identity::new(user, password) else {
                    return NO_MEMORY;
                };
                let cred = (&raw mut identity.c).cast::<u8>();
                // SAFETY: a live session; no name; the identity, whose
                // strings live in `identity` across the call.
                Code(unsafe { sys::ldap_bind_sA(self.ld, ptr::null(), cred, method) } as i32)
            }
            WinBind::CurrentUser => {
                // SAFETY: a live session; no name and no identity, the
                // process's user's then.
                let rc =
                    unsafe { sys::ldap_bind_sA(self.ld, ptr::null(), ptr::null(), AUTH_NEGOTIATE) };
                Code(rc as i32)
            }
        }
    }
}

/// `s` as a C string for the library, or the library's code for why it
/// cannot be one.
fn c_string(s: &[u8]) -> Result<Vec<u8>, Code> {
    match terminated(s) {
        Ok(Some(z)) => Ok(z),
        Ok(None) => Err(PARAM_ERROR),
        Err(OutOfMemory) => Err(NO_MEMORY),
    }
}

impl Session {
    /// A simple bind, which `ldap_win_bind` makes with a login alone.
    fn simple_bind(&mut self, user: &[u8], password: &[u8]) -> Code {
        let (user, password) = match (c_string(user), c_string(password)) {
            (Ok(u), Ok(p)) => (u, p),
            (Err(c), _) | (_, Err(c)) => return c,
        };
        // SAFETY: a live session, and C strings the call reads.
        Code(unsafe { sys::ldap_simple_bind_sA(self.ld, user.as_ptr(), password.as_ptr()) } as i32)
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        // SAFETY: the session, unbound and freed once, here, no answer of
        // it alive: those borrow the session.
        unsafe { sys::ldap_unbind_s(self.ld) };
    }
}

/// An SSPI identity as `Curl_create_sspi_identity` makes one: the user
/// past a `\` or else a `/`, the domain before it, and the password, as
/// ANSI strings with their lengths.
struct Identity {
    c: SEC_WINNT_AUTH_IDENTITY_EXA,
    /// The strings `c` points into, which do not move as `Identity`
    /// does.
    user: Vec<u8>,
    domain: Vec<u8>,
    password: Vec<u8>,
}

impl Identity {
    fn new(user_and_domain: &[u8], password: &[u8]) -> Result<Identity, OutOfMemory> {
        // C's strings end at a NUL.
        let user_and_domain = c_text(user_and_domain);
        let password = c_text(password);
        let split = user_and_domain
            .iter()
            .position(|&b| b == b'\\')
            .or_else(|| user_and_domain.iter().position(|&b| b == b'/'));
        let (domain, user) = match split {
            Some(at) => (&user_and_domain[..at], &user_and_domain[at + 1..]),
            None => (&b""[..], user_and_domain),
        };
        let z = |s: &[u8]| terminated(s).map(|z| z.expect("cut at its NUL"));
        let mut id = Identity {
            c: SEC_WINNT_AUTH_IDENTITY_EXA {
                Version: SEC_WINNT_AUTH_IDENTITY_VERSION,
                Length: size_of::<SEC_WINNT_AUTH_IDENTITY_EXA>() as u32,
                User: ptr::null_mut(),
                UserLength: user.len() as u32,
                Domain: ptr::null_mut(),
                DomainLength: domain.len() as u32,
                Password: ptr::null_mut(),
                PasswordLength: password.len() as u32,
                Flags: IDENTITY_ANSI,
                PackageList: ptr::null_mut(),
                PackageListLength: 0,
            },
            user: z(user)?,
            domain: z(domain)?,
            password: z(password)?,
        };
        id.c.User = id.user.as_mut_ptr();
        id.c.Domain = id.domain.as_mut_ptr();
        id.c.Password = id.password.as_mut_ptr();
        Ok(id)
    }
}

/// `s` as C reads it, up to a NUL.
fn c_text(s: &[u8]) -> &[u8] {
    s.split(|&b| b == 0).next().unwrap_or_default()
}

impl Drop for Identity {
    /// The password wiped, as C's `Curl_sspi_free_identity` wipes it.
    fn drop(&mut self) {
        self.password.fill(0);
        // Kept from being optimised away as a write never read.
        core::hint::black_box(&self.password);
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
    dn: *mut u8,
    /// The attribute read, and its values.
    attr: *mut u8,
    vals: *mut *mut sys::LDAP_BERVAL,
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
            unsafe { sys::ldap_memfreeA(self.attr) };
            self.attr = ptr::null_mut();
        }
    }

    /// Free what was read of the entry.
    fn free_entry(&mut self) {
        self.free_attribute();
        if !self.dn.is_null() {
            // SAFETY: the library's string, freed once.
            unsafe { sys::ldap_memfreeA(self.dn) };
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
            unsafe { sys::ldap_memfreeA(self.dn) };
        }
        // SAFETY: a live session, and an entry of its answer.
        self.dn = unsafe { sys::ldap_get_dnA(self.ld, self.entry) };
        if self.dn.is_null() {
            return Err(NoName::Missing);
        }
        // SAFETY: the library's C string, freed only as `self` reads
        // another or is dropped, which `&mut self` keeps from happening
        // while the bytes are borrowed.
        Ok(unsafe { CStr::from_ptr(self.dn.cast::<c_char>()) }.to_bytes())
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
            unsafe { sys::ldap_next_attributeA(self.ld, self.entry, self.ber) }
        } else {
            self.attrs_started = true;
            // SAFETY: a live session, an entry of its answer, and where
            // the place in its attributes goes.
            unsafe { sys::ldap_first_attributeA(self.ld, self.entry, &raw mut self.ber) }
        };
        if self.attr.is_null() {
            return Ok(None);
        }
        // SAFETY: a live session, an entry of its answer, and the C
        // string of one of its attributes.
        self.vals = unsafe { sys::ldap_get_values_lenA(self.ld, self.entry, self.attr) };
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
                let value: &[u8] = if bv.bv_val.is_null() {
                    &[]
                } else {
                    let len = usize::try_from(bv.bv_len).expect("a length in memory");
                    // SAFETY: the library's value, `bv_len` bytes at
                    // `bv_val`, freed only as `self` reads another
                    // attribute or is dropped, which the borrow of `self`
                    // keeps from happening.
                    unsafe { core::slice::from_raw_parts(bv.bv_val.cast_const(), len) }
                };
                all.try_push(value)?;
            }
            Some(all)
        };
        // SAFETY: the library's C string, freed as the values are.
        let name = unsafe { CStr::from_ptr(self.attr.cast::<c_char>()) }.to_bytes();
        Ok(Some(Attribute { name, values }))
    }
}

#[cfg(test)]
#[path = "win_tests.rs"]
mod tests;
