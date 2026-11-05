//! LDAP from WinLDAP (`wldap32`) as `lib/ldap.c` drives it with
//! `USE_WIN32_LDAP`: a session of the library's own to the host and port
//! (`ldap_init`, `ldap_sslinit` for `ldaps:`), each call waiting for its
//! answer, binds made as `ldap_win_bind` makes them, simply or by SSPI,
//! and the entries of the search's answer read in turn. The URL is read
//! by C's own parser, as WinLDAP has none.
//!
//! C's calls are the library's `TCHAR` ones: the ANSI calls in a build
//! without `UNICODE`, handed the bytes as they are, and in the Unicode
//! build (`curl_os::UNICODE`) the wide ones, handed the strings converted
//! from UTF-8 to UTF-16 and their answers converted back.

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
    SEC_WINNT_AUTH_IDENTITY_EXA, SEC_WINNT_AUTH_IDENTITY_EXW, SEC_WINNT_AUTH_IDENTITY_VERSION,
};
use windows_sys::Win32::Security::Cryptography::{CERT_CONTEXT, CertFreeCertificateContext};

use crate::strings::{c_list, terminated, utf8_of_wide, wide_terminated};

/// WinLDAP, as `lib/ldap.c` drives it: through its wide calls in the
/// Unicode build, its ANSI ones otherwise.
#[derive(Debug)]
pub struct WinLdap {
    wide: bool,
}

/// The library each handle speaks LDAP with.
pub static WINLDAP: WinLdap = WinLdap {
    wide: curl_os::UNICODE,
};

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

/// An identity's strings are in the ANSI code page, or in UTF-16
/// (`SEC_WINNT_AUTH_IDENTITY_ANSI`, `SEC_WINNT_AUTH_IDENTITY_UNICODE`).
const IDENTITY_ANSI: u32 = 1;
const IDENTITY_UNICODE: u32 = 2;

/// `LDAP_OPT_ON`, an option's value as a pointer.
const OPT_ON: *const c_void = ptr::without_provenance(1);

impl Local for WinLdap {
    fn vendor(&self) -> (&'static str, i32) {
        VENDOR
    }

    /// C's own parser, its errors in the library's codes; in the Unicode
    /// build each part it reads must be UTF-8, as it converts them.
    fn parse_url(&self, url: &LocalUrl<'_>) -> Result<Search, UrlError> {
        parse_url_low(url.path, url.query, self.wide).map_err(|e| match e {
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
        // A name with a NUL reaches no host.
        if host.contains(&0) {
            return Err(Opened::Refused);
        }
        let port = u32::from(port);
        let ld = if self.wide {
            // A name C cannot convert fails as if memory ran out.
            let Ok(Some(host)) = wide_terminated(host) else {
                return Err(Opened::OutOfMemory);
            };
            if secured {
                // SAFETY: a wide C string the library copies; a port; TLS
                // on.
                unsafe { sys::ldap_sslinitW(host.as_ptr(), port, 1) }
            } else {
                // SAFETY: a wide C string the library copies, and a port.
                unsafe { sys::ldap_initW(host.as_ptr(), port) }
            }
        } else {
            let Ok(Some(host)) = terminated(host) else {
                return Err(Opened::OutOfMemory);
            };
            if secured {
                // SAFETY: a C string the library copies; a port; TLS on.
                unsafe { sys::ldap_sslinitA(host.as_ptr(), port, 1) }
            } else {
                // SAFETY: a C string the library copies, and a port.
                unsafe { sys::ldap_initA(host.as_ptr(), port) }
            }
        };
        if ld.is_null() {
            return Err(Opened::Refused);
        }
        // A box that cannot be made drops the session, which frees it.
        let session = Session {
            ld,
            wide: self.wide,
        };
        match curl_alloc::try_box(session) {
            Ok(b) => Ok(LocalSession::Windows(b)),
            Err(OutOfMemory) => Err(Opened::OutOfMemory),
        }
    }
}

/// A session the library made, unbound as it is dropped, and whether it
/// is driven through the wide calls.
#[derive(Debug)]
struct Session {
    ld: *mut sys::LDAP,
    wide: bool,
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
        let scope = match search.scope {
            Scope::Base => sys::LDAP_SCOPE_BASE,
            Scope::OneLevel => sys::LDAP_SCOPE_ONELEVEL,
            Scope::Subtree => sys::LDAP_SCOPE_SUBTREE,
            Scope::Subordinate => unreachable!("C's parser reads no such scope"),
        };
        let mut res: *mut sys::LDAPMessage = ptr::null_mut();
        let rc = if self.wide {
            let z = |s: &[u8]| text(s, wide_terminated);
            let dn = search.dn.as_deref().map(z).transpose()?;
            let filter = search.filter.as_deref().map(z).transpose()?;
            let mut attrs = Vec::new();
            for a in search.attrs.iter().flatten() {
                attrs.try_push(z(a)?).map_err(|OutOfMemory| NO_MEMORY)?;
            }
            let list = match search.attrs {
                Some(_) => Some(wide_list(&attrs).map_err(|OutOfMemory| NO_MEMORY)?),
                None => None,
            };
            let c = |z: &Option<Vec<u16>>| z.as_ref().map_or(ptr::null(), |z| z.as_ptr());
            let list = list.as_ref().map_or(ptr::null(), |l| l.as_ptr());
            // SAFETY: a live session; NULL or wide C strings, and NULL or
            // a NULL-terminated list of them, which live across the call
            // and which the library only reads; where the answer goes.
            unsafe {
                sys::ldap_search_sW(self.ld, c(&dn), scope, c(&filter), list, 0, &raw mut res)
            }
        } else {
            let z = |s: &[u8]| text(s, terminated);
            let dn = search.dn.as_deref().map(z).transpose()?;
            let filter = search.filter.as_deref().map(z).transpose()?;
            let mut attrs = Vec::new();
            for a in search.attrs.iter().flatten() {
                attrs.try_push(z(a)?).map_err(|OutOfMemory| NO_MEMORY)?;
            }
            let list = match search.attrs {
                Some(_) => Some(c_list(&attrs).map_err(|OutOfMemory| NO_MEMORY)?),
                None => None,
            };
            let c = |z: &Option<Vec<u8>>| z.as_ref().map_or(ptr::null(), |z| z.as_ptr());
            let list = list
                .as_ref()
                .map_or(ptr::null(), |l| l.as_ptr().cast::<*const i8>());
            // SAFETY: a live session; NULL or C strings, and NULL or a
            // NULL-terminated list of them, which live across the call and
            // which the library only reads; where the answer goes.
            unsafe {
                sys::ldap_search_sA(self.ld, c(&dn), scope, c(&filter), list, 0, &raw mut res)
            }
        };
        let found = Found {
            ld: self.ld,
            wide: self.wide,
            res,
            entry: ptr::null_mut(),
            started: false,
            ber: ptr::null_mut(),
            attrs_started: false,
            dn: None,
            attr: None,
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
                let rc = if self.wide {
                    // A login C cannot convert fails as if memory ran out.
                    let (Ok(Some(user)), Ok(Some(password))) = (
                        wide_terminated(c_text(user)),
                        wide_terminated(c_text(password)),
                    ) else {
                        return NO_MEMORY;
                    };
                    let Ok(mut identity) = Identity::new(&user, &password) else {
                        return NO_MEMORY;
                    };
                    let mut c = identity.wide();
                    let cred = (&raw mut c).cast::<u16>();
                    // SAFETY: a live session; no name; the identity, whose
                    // strings live in `identity` across the call.
                    unsafe { sys::ldap_bind_sW(self.ld, ptr::null(), cred, method) }
                } else {
                    let Ok(mut identity) = Identity::new(user, password) else {
                        return NO_MEMORY;
                    };
                    let mut c = identity.ansi();
                    let cred = (&raw mut c).cast::<u8>();
                    // SAFETY: as above, the ANSI call.
                    unsafe { sys::ldap_bind_sA(self.ld, ptr::null(), cred, method) }
                };
                Code(rc as i32)
            }
            WinBind::CurrentUser => {
                let rc = if self.wide {
                    // SAFETY: a live session; no name and no identity, the
                    // process's user's then.
                    unsafe { sys::ldap_bind_sW(self.ld, ptr::null(), ptr::null(), AUTH_NEGOTIATE) }
                } else {
                    // SAFETY: as above, the ANSI call.
                    unsafe { sys::ldap_bind_sA(self.ld, ptr::null(), ptr::null(), AUTH_NEGOTIATE) }
                };
                Code(rc as i32)
            }
        }
    }
}

/// A string made for the library: none where it cannot be.
type Convert<T> = fn(&[u8]) -> Result<Option<Vec<T>>, OutOfMemory>;

/// `s` as a string for the library, made by `convert`, or the library's
/// code for why it cannot be one: a NUL inside is a parameter the library
/// cannot take; anything else, as C has it, is memory run out.
fn text<T>(s: &[u8], convert: Convert<T>) -> Result<Vec<T>, Code> {
    if s.contains(&0) {
        return Err(PARAM_ERROR);
    }
    match convert(s) {
        Ok(Some(z)) => Ok(z),
        Ok(None) | Err(OutOfMemory) => Err(NO_MEMORY),
    }
}

/// A NULL-terminated list of the wide C strings `zs` hold.
fn wide_list(zs: &[Vec<u16>]) -> Result<Vec<*const u16>, OutOfMemory> {
    let mut list = Vec::new();
    list.try_reserve_exact(zs.len() + 1)?;
    for z in zs {
        list.try_push(z.as_ptr())?;
    }
    list.try_push(ptr::null())?;
    Ok(list)
}

impl Session {
    /// A simple bind, which `ldap_win_bind` makes with a login alone. In
    /// the Unicode build a part C cannot convert is handed over as NULL,
    /// as C hands it.
    fn simple_bind(&mut self, user: &[u8], password: &[u8]) -> Code {
        if user.contains(&0) || password.contains(&0) {
            return PARAM_ERROR;
        }
        let rc = if self.wide {
            let (Ok(user), Ok(password)) = (wide_terminated(user), wide_terminated(password))
            else {
                return NO_MEMORY;
            };
            let c = |z: &Option<Vec<u16>>| z.as_ref().map_or(ptr::null(), |z| z.as_ptr());
            // SAFETY: a live session, and NULL or wide C strings the call
            // reads.
            unsafe { sys::ldap_simple_bind_sW(self.ld, c(&user), c(&password)) }
        } else {
            let (Ok(Some(user)), Ok(Some(password))) = (terminated(user), terminated(password))
            else {
                return NO_MEMORY;
            };
            // SAFETY: a live session, and C strings the call reads.
            unsafe { sys::ldap_simple_bind_sA(self.ld, user.as_ptr(), password.as_ptr()) }
        };
        Code(rc as i32)
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        // SAFETY: the session, unbound and freed once, here, no answer of
        // it alive: those borrow the session.
        unsafe { sys::ldap_unbind_s(self.ld) };
    }
}

/// A unit of a C string an identity is made of: a byte in the ANSI code
/// page, or a UTF-16 unit.
trait Unit: Copy + Default + PartialEq + From<u8> {}
impl Unit for u8 {}
impl Unit for u16 {}

/// An SSPI identity as `Curl_create_sspi_identity` makes one: the user
/// past a `\` or else a `/`, the domain before it, and the password, each
/// with a NUL after it.
struct Identity<T: Unit> {
    user: Vec<T>,
    domain: Vec<T>,
    password: Vec<T>,
}

impl<T: Unit> Identity<T> {
    fn new(user_and_domain: &[T], password: &[T]) -> Result<Identity<T>, OutOfMemory> {
        // C's strings end at a NUL.
        let user_and_domain = c_text(user_and_domain);
        let password = c_text(password);
        let at = |c: u8| user_and_domain.iter().position(|&u| u == T::from(c));
        let (domain, user) = match at(b'\\').or_else(|| at(b'/')) {
            Some(at) => (&user_and_domain[..at], &user_and_domain[at + 1..]),
            None => (&[][..], user_and_domain),
        };
        let z = |s: &[T]| -> Result<Vec<T>, OutOfMemory> {
            let mut z = Vec::new();
            z.try_reserve_exact(s.len() + 1)?;
            z.try_extend_from_slice(s)?;
            z.try_push(T::default())?;
            Ok(z)
        };
        Ok(Identity {
            user: z(user)?,
            domain: z(domain)?,
            password: z(password)?,
        })
    }
}

/// A string's length, its NUL aside, as the identity counts it.
fn length<T>(z: &[T]) -> u32 {
    u32::try_from(z.len() - 1).expect("a login's length fits")
}

impl Identity<u8> {
    /// The identity as the ANSI calls take it, pointing into `self`.
    fn ansi(&mut self) -> SEC_WINNT_AUTH_IDENTITY_EXA {
        SEC_WINNT_AUTH_IDENTITY_EXA {
            Version: SEC_WINNT_AUTH_IDENTITY_VERSION,
            Length: size_of::<SEC_WINNT_AUTH_IDENTITY_EXA>() as u32,
            UserLength: length(&self.user),
            User: self.user.as_mut_ptr(),
            DomainLength: length(&self.domain),
            Domain: self.domain.as_mut_ptr(),
            PasswordLength: length(&self.password),
            Password: self.password.as_mut_ptr(),
            Flags: IDENTITY_ANSI,
            PackageList: ptr::null_mut(),
            PackageListLength: 0,
        }
    }
}

impl Identity<u16> {
    /// The identity as the wide calls take it, pointing into `self`.
    fn wide(&mut self) -> SEC_WINNT_AUTH_IDENTITY_EXW {
        SEC_WINNT_AUTH_IDENTITY_EXW {
            Version: SEC_WINNT_AUTH_IDENTITY_VERSION,
            Length: size_of::<SEC_WINNT_AUTH_IDENTITY_EXW>() as u32,
            UserLength: length(&self.user),
            User: self.user.as_mut_ptr(),
            DomainLength: length(&self.domain),
            Domain: self.domain.as_mut_ptr(),
            PasswordLength: length(&self.password),
            Password: self.password.as_mut_ptr(),
            Flags: IDENTITY_UNICODE,
            PackageList: ptr::null_mut(),
            PackageListLength: 0,
        }
    }
}

/// `s` as C reads it, up to a NUL.
fn c_text<T: Copy + Default + PartialEq>(s: &[T]) -> &[T] {
    let end = s.iter().position(|&u| u == T::default()).unwrap_or(s.len());
    &s[..end]
}

impl<T: Unit> Drop for Identity<T> {
    /// The password wiped, as C's `Curl_sspi_free_identity` wipes it.
    fn drop(&mut self) {
        self.password.fill(T::default());
        // Kept from being optimised away as a write never read.
        core::hint::black_box(&self.password);
    }
}

/// A string the library made, freed as it is dropped: the ANSI calls'
/// as it is, the wide calls' with its UTF-8 form, as C converts it.
enum LibraryText {
    Ansi(*mut u8),
    Wide(*mut u16, Vec<u8>),
}

impl LibraryText {
    /// The library's string `p`, not NULL, of the wide calls if `wide`:
    /// none where its UTF-8 form cannot be made, the string freed.
    ///
    /// # Safety
    ///
    /// `p` is a C string of the library's, of the kind `wide` says, that
    /// is the caller's to free with `ldap_memfree`.
    unsafe fn new(p: *mut c_void, wide: bool) -> Result<LibraryText, OutOfMemory> {
        if !wide {
            return Ok(LibraryText::Ansi(p.cast()));
        }
        let p = p.cast::<u16>();
        let mut len = 0;
        loop {
            // SAFETY: a wide C string, read up to its NUL: `len` is at
            // most its NUL's place.
            let at = unsafe { p.add(len) };
            // SAFETY: a unit of the string, as above.
            if unsafe { at.read() } == 0 {
                break;
            }
            len += 1;
        }
        // SAFETY: the string's `len` units, as counted.
        let units = unsafe { core::slice::from_raw_parts(p, len) };
        match utf8_of_wide(units) {
            Ok(utf8) => Ok(LibraryText::Wide(p, utf8)),
            Err(OutOfMemory) => {
                // SAFETY: the library's string, freed once.
                unsafe { sys::ldap_memfreeW(p) };
                Err(OutOfMemory)
            }
        }
    }

    /// Its bytes: the ANSI string's, the wide one's UTF-8.
    fn bytes(&self) -> &[u8] {
        match self {
            // SAFETY: the library's C string, freed only as `self` is
            // dropped.
            LibraryText::Ansi(p) => unsafe { CStr::from_ptr(p.cast::<c_char>()) }.to_bytes(),
            LibraryText::Wide(_, utf8) => utf8,
        }
    }
}

impl Drop for LibraryText {
    fn drop(&mut self) {
        match *self {
            // SAFETY: the library's string, freed once.
            LibraryText::Ansi(p) => unsafe { sys::ldap_memfreeA(p) },
            // SAFETY: as above.
            LibraryText::Wide(p, _) => unsafe { sys::ldap_memfreeW(p) },
        }
    }
}

/// A search's answer, its entries read in turn, each the library's until
/// the next is read, and the whole freed as it is dropped.
struct Found<'s> {
    ld: *mut sys::LDAP,
    /// Whether the session is driven through the wide calls.
    wide: bool,
    /// The answer, NULL for none.
    res: *mut sys::LDAPMessage,
    /// The entry read, NULL before the first and after the last.
    entry: *mut sys::LDAPMessage,
    started: bool,
    /// Where the library is in the entry's attributes.
    ber: *mut sys::BerElement,
    attrs_started: bool,
    /// The entry's name, as last read.
    dn: Option<LibraryText>,
    /// The attribute read, and its values.
    attr: Option<LibraryText>,
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
        self.attr = None;
    }

    /// Free what was read of the entry.
    fn free_entry(&mut self) {
        self.free_attribute();
        self.dn = None;
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
        self.dn = None;
        let dn: *mut c_void = if self.wide {
            // SAFETY: a live session, and an entry of its answer.
            unsafe { sys::ldap_get_dnW(self.ld, self.entry) }.cast()
        } else {
            // SAFETY: as above, the ANSI call.
            unsafe { sys::ldap_get_dnA(self.ld, self.entry) }.cast()
        };
        if dn.is_null() {
            return Err(NoName::Missing);
        }
        // SAFETY: the library's string, of the calls `self.wide` names,
        // this reader's to free.
        let dn = unsafe { LibraryText::new(dn, self.wide) }.map_err(|_| NoName::OutOfMemory)?;
        Ok(self.dn.insert(dn).bytes())
    }

    fn next_attribute(&mut self) -> Result<Option<Attribute<'_>>, OutOfMemory> {
        assert!(!self.entry.is_null(), "an entry is read");
        self.free_attribute();
        let attr: *mut c_void = if self.attrs_started {
            if self.ber.is_null() {
                return Ok(None);
            }
            if self.wide {
                // SAFETY: a live session, an entry of its answer, and the
                // place the first call left in its attributes.
                unsafe { sys::ldap_next_attributeW(self.ld, self.entry, self.ber) }.cast()
            } else {
                // SAFETY: as above, the ANSI call.
                unsafe { sys::ldap_next_attributeA(self.ld, self.entry, self.ber) }.cast()
            }
        } else {
            self.attrs_started = true;
            if self.wide {
                // SAFETY: a live session, an entry of its answer, and where
                // the place in its attributes goes.
                unsafe { sys::ldap_first_attributeW(self.ld, self.entry, &raw mut self.ber) }.cast()
            } else {
                // SAFETY: as above, the ANSI call.
                unsafe { sys::ldap_first_attributeA(self.ld, self.entry, &raw mut self.ber) }.cast()
            }
        };
        if attr.is_null() {
            return Ok(None);
        }
        // SAFETY: the library's string, of the calls `self.wide` names,
        // this reader's to free.
        let attr = self
            .attr
            .insert(unsafe { LibraryText::new(attr, self.wide) }?);
        self.vals = match *attr {
            // SAFETY: a live session, an entry of its answer, and the C
            // string of one of its attributes, as the library gave it.
            LibraryText::Ansi(p) => unsafe { sys::ldap_get_values_lenA(self.ld, self.entry, p) },
            // SAFETY: as above, the wide call.
            LibraryText::Wide(p, _) => unsafe { sys::ldap_get_values_lenW(self.ld, self.entry, p) },
        };
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
        let name = self.attr.as_ref().expect("read above").bytes();
        Ok(Some(Attribute { name, values }))
    }
}

#[cfg(test)]
#[path = "win_tests.rs"]
mod tests;
