//! What the two ways of driving the library share (`lib/openldap.c`'s
//! and `lib/ldap.c`'s): the URL's search as libldap parses it, its words
//! for a code, its version, and the conversions between Rust's bytes and
//! the library's strings and values.

#![allow(unsafe_code)]
#![cfg_attr(test, allow(clippy::disallowed_methods, clippy::disallowed_macros))]

use core::ffi::{CStr, c_char, c_int, c_void};
use core::ptr;
use std::sync::OnceLock;

use curl_alloc::{OutOfMemory, TryVec as _};
use curl_core::ldap::{Code, Scope, Search, UrlError};

pub(crate) use crate::strings::{c_list, terminated};
use crate::sys;

/// What `curl -V` names the library as, made once (`Curl_ldap_version`).
pub(crate) type Words = OnceLock<([u8; 64], usize)>;

/// The library's version, as `curl -V` names it (`Curl_ldap_version`):
/// its vendor's name and its number, then `flavor`, `OpenLDAP/2.6.15`;
/// `fallback` where the library will not say. Made once into `words`.
pub(crate) fn version(words: &'static Words, flavor: &str, fallback: &str) -> &'static str {
    let (buf, len) = words.get_or_init(|| api_version(flavor, fallback));
    core::str::from_utf8(&buf[..*len]).expect("the library names itself in ASCII")
}

/// The words of [`version`], as the library gives them, else
/// `fallback`.
fn api_version(flavor: &str, fallback: &str) -> ([u8; 64], usize) {
    use std::io::Write as _;
    let mut buf = [0u8; 64];
    let mut api = sys::LDAPAPIInfo {
        ldapai_info_version: sys::LDAP_API_INFO_VERSION,
        ldapai_api_version: 0,
        ldapai_protocol_version: 0,
        ldapai_extensions: ptr::null_mut(),
        ldapai_vendor_name: ptr::null_mut(),
        ldapai_vendor_version: 0,
    };
    // SAFETY: with no session, the option fills the struct, whose
    // version it is told, and allocates its name and extensions.
    let rc = unsafe {
        sys::ldap_get_option(
            ptr::null_mut(),
            sys::LDAP_OPT_API_INFO,
            (&raw mut api).cast::<c_void>(),
        )
    };
    let mut out = &mut buf[..];
    let room = out.len();
    if rc == sys::LDAP_OPT_SUCCESS && !api.ldapai_vendor_name.is_null() {
        // SAFETY: a C string the library allocated, freed below.
        let vendor = unsafe { CStr::from_ptr(api.ldapai_vendor_name) };
        let (major, minor, patch) =
            vendor_version(u32::try_from(api.ldapai_vendor_version).unwrap_or(0));
        let said = out
            .write_all(vendor.to_bytes())
            .and_then(|()| write!(out, "/{major}.{minor}.{patch}{flavor}"));
        assert!(said.is_ok(), "the version fits its buffer");
        // SAFETY: allocated by the call above, freed once each.
        unsafe { sys::ldap_memfree(api.ldapai_vendor_name.cast::<c_void>()) };
        // SAFETY: as above; the vector is NULL or the library's.
        unsafe { sys::ber_memvfree(api.ldapai_extensions.cast::<*mut c_void>()) };
    } else {
        assert!(out.write_all(fallback.as_bytes()).is_ok(), "fits");
    }
    let len = room - out.len();
    (buf, len)
}

/// The vendor's version number as its major, minor and patch numbers, as
/// C splits it (`Curl_ldap_version`).
pub(crate) fn vendor_version(v: u32) -> (u32, u32, u32) {
    let (major, patch) = (v / 10000, v % 100);
    (major, (v - major * 10000 - patch) / 100, patch)
}

/// A C string's bytes, copied; none for NULL.
///
/// # Safety
///
/// `s` is NULL or a C string that lives for the call.
pub(crate) unsafe fn copied(s: *const c_char) -> Result<Option<Vec<u8>>, OutOfMemory> {
    if s.is_null() {
        return Ok(None);
    }
    // SAFETY: not NULL, a C string, as the caller says.
    let bytes = unsafe { CStr::from_ptr(s) }.to_bytes();
    let mut out = Vec::new();
    out.try_extend_from_slice(bytes)?;
    Ok(Some(out))
}

/// The bytes a `berval` holds; none for one without any.
///
/// # Safety
///
/// `bv` is a value libldap filled, living as long as `'a`.
pub(crate) unsafe fn bytes<'a>(bv: &sys::berval) -> Option<&'a [u8]> {
    if bv.bv_val.is_null() {
        return None;
    }
    let len = usize::try_from(bv.bv_len).expect("a length in memory");
    // SAFETY: libldap's value: `bv_len` bytes at `bv_val`, which live as
    // long as the caller says.
    Some(unsafe { core::slice::from_raw_parts(bv.bv_val.cast::<u8>(), len) })
}

/// The scope the library read in a URL; none for one it numbers but no
/// search here is made with.
fn scope_of(n: c_int) -> Option<Scope> {
    match n {
        sys::LDAP_SCOPE_BASE => Some(Scope::Base),
        sys::LDAP_SCOPE_ONELEVEL => Some(Scope::OneLevel),
        sys::LDAP_SCOPE_SUBTREE => Some(Scope::Subtree),
        sys::LDAP_SCOPE_SUBORDINATE => Some(Scope::Subordinate),
        _ => None,
    }
}

/// The library's number for `scope`.
pub(crate) fn scope_number(scope: Scope) -> c_int {
    match scope {
        Scope::Base => sys::LDAP_SCOPE_BASE,
        Scope::OneLevel => sys::LDAP_SCOPE_ONELEVEL,
        Scope::Subtree => sys::LDAP_SCOPE_SUBTREE,
        Scope::Subordinate => sys::LDAP_SCOPE_SUBORDINATE,
    }
}

pub(crate) fn parse_url(url: &[u8]) -> Result<Search, UrlError> {
    let mem = |OutOfMemory| UrlError::MEM;
    let Some(url) = terminated(url).map_err(mem)? else {
        return Err(UrlError::BAD_URL);
    };
    let mut lud: *mut sys::LDAPURLDesc = ptr::null_mut();
    // SAFETY: a C string, and where the description goes.
    let rc = unsafe { sys::ldap_url_parse(url.as_ptr().cast::<c_char>(), &raw mut lud) };
    if rc != sys::LDAP_URL_SUCCESS {
        // SAFETY: NULL, which the library takes as nothing, or its
        // description, freed once.
        unsafe { sys::ldap_free_urldesc(lud) };
        return Err(UrlError(rc));
    }
    assert!(!lud.is_null(), "a URL parsed is described");
    let search = (|| {
        // SAFETY: the description the library made, freed below.
        let d = unsafe { &*lud };
        // SAFETY: NULL or the library's C strings, alive until the
        // description is freed.
        let dn = unsafe { copied(d.lud_dn) }.map_err(mem)?;
        // SAFETY: as above.
        let filter = unsafe { copied(d.lud_filter) }.map_err(mem)?;
        let attrs = if d.lud_attrs.is_null() {
            None
        } else {
            let mut all = Vec::new();
            for i in 0.. {
                // SAFETY: a NULL-terminated list, read up to its NULL:
                // `i` is at most its NULL's place.
                let at = unsafe { d.lud_attrs.add(i) };
                // SAFETY: an element of the list, as above.
                let a = unsafe { at.read() };
                if a.is_null() {
                    break;
                }
                // SAFETY: one of the list's C strings.
                let a = unsafe { copied(a) }.map_err(mem)?.expect("not NULL");
                all.try_push(a).map_err(mem)?;
            }
            Some(all)
        };
        Ok(Search {
            dn,
            scope: scope_of(d.lud_scope).ok_or(UrlError(sys::LDAP_URL_ERR_BADSCOPE))?,
            filter,
            attrs,
        })
    })();
    // SAFETY: the library's description, freed once, not used after.
    unsafe { sys::ldap_free_urldesc(lud) };
    search
}

pub(crate) fn describe(code: Code) -> &'static [u8] {
    // SAFETY: any number; the library's static words for it.
    let s = unsafe { sys::ldap_err2string(code.0) };
    assert!(!s.is_null(), "the library has words for every code");
    // SAFETY: a static C string of the library's.
    unsafe { CStr::from_ptr(s) }.to_bytes()
}

/// A search's base, filter and attributes as C strings, and the attributes'
/// NULL-terminated list, for the library's search calls.
pub(crate) struct CSearch {
    dn: Option<Vec<u8>>,
    filter: Option<Vec<u8>>,
    /// The attributes' C strings, which `list` points into: their bytes
    /// do not move as the struct does.
    _attrs: Option<Vec<Vec<u8>>>,
    list: Option<Vec<*mut c_char>>,
}

impl CSearch {
    /// `search`'s strings for the library; a string it could not be given
    /// is out of memory, as no URL the library parsed has a NUL.
    pub(crate) fn new(search: &Search) -> Result<CSearch, Code> {
        let nomem = |OutOfMemory| Code::NO_MEMORY;
        let z = |s: &Option<Vec<u8>>| match s {
            Some(s) => terminated(s)
                .map_err(nomem)?
                .ok_or(Code::NO_MEMORY)
                .map(Some),
            None => Ok(None),
        };
        let dn = z(&search.dn)?;
        let filter = z(&search.filter)?;
        let attrs = match &search.attrs {
            Some(attrs) => {
                let mut zs = Vec::new();
                zs.try_reserve_exact(attrs.len())
                    .map_err(|_| Code::NO_MEMORY)?;
                for a in attrs {
                    zs.try_push(terminated(a).map_err(nomem)?.ok_or(Code::NO_MEMORY)?)
                        .map_err(nomem)?;
                }
                Some(zs)
            }
            None => None,
        };
        let list = match &attrs {
            Some(zs) => Some(c_list(zs).map_err(nomem)?),
            None => None,
        };
        Ok(CSearch {
            dn,
            filter,
            _attrs: attrs,
            list,
        })
    }

    /// The base, a C string, or NULL.
    pub(crate) fn dn(&self) -> *const c_char {
        self.dn
            .as_ref()
            .map_or(ptr::null(), |d| d.as_ptr().cast::<c_char>())
    }

    /// The filter, a C string, or NULL.
    pub(crate) fn filter(&self) -> *const c_char {
        self.filter
            .as_ref()
            .map_or(ptr::null(), |f| f.as_ptr().cast::<c_char>())
    }

    /// The attributes, a NULL-terminated list, or NULL.
    pub(crate) fn attrs(&mut self) -> *mut *mut c_char {
        self.list
            .as_mut()
            .map_or(ptr::null_mut(), |l| l.as_mut_ptr())
    }
}

#[cfg(test)]
#[path = "common_tests.rs"]
mod tests;
