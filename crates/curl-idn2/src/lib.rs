//! Internationalized host names from libidn2 (`lib/idn.c`): a name in
//! the locale's characters looked up by its punycode form, and a name in
//! punycode shown in Unicode.

#![allow(unsafe_code)]
#![cfg_attr(test, allow(clippy::disallowed_methods, clippy::disallowed_macros))]

use core::ffi::{CStr, c_char, c_int, c_void};

use curl_alloc::TryVec as _;
use curl_core::idn::{Idn, IdnFailure};

/// libidn2, as C's build uses it.
#[derive(Debug)]
pub struct Idn2;

/// The library each handle converts its names with.
pub static IDN2: Idn2 = Idn2;

/// The library's version, as `curl -V` names it (`idn2_check_version`).
pub fn version() -> &'static str {
    version_c().to_str().expect("libidn2's version is ASCII")
}

/// The library's version as `curl_version_info` gives it, a C string the
/// library keeps.
pub fn version_c() -> &'static CStr {
    // SAFETY: with NULL, `idn2_check_version` returns the library's
    // version, a string of its own that lives as long as the process.
    let v = unsafe { idn2_check_version(core::ptr::null()) };
    assert!(!v.is_null(), "libidn2 names its version");
    // SAFETY: as above, a C string libidn2 keeps.
    unsafe { CStr::from_ptr(v) }
}

/// `IDN2_NFC_INPUT`, `IDN2_TRANSITIONAL` and `IDN2_NONTRANSITIONAL`.
const NFC_INPUT: c_int = 1;
const TRANSITIONAL: c_int = 4;
const NONTRANSITIONAL: c_int = 8;
/// `IDN2_OK` and `IDN2_MALLOC`.
const OK: c_int = 0;
const MALLOC: c_int = -100;
/// The oldest libidn2 C asks for, which has non-transitional processing
/// (`IDN2_VERSION_NUMBER >= 0x00140000`).
const WANTED: &CStr = c"0.20.0";

unsafe extern "C" {
    fn idn2_check_version(req_version: *const c_char) -> *const c_char;
    fn idn2_lookup_ul(src: *const c_char, lookupname: *mut *mut c_char, flags: c_int) -> c_int;
    fn idn2_to_unicode_8z8z(input: *const c_char, output: *mut *mut c_char, flags: c_int) -> c_int;
    fn idn2_free(ptr: *mut c_void);
}

/// A string libidn2 made, freed with it.
struct Made(*mut c_char);

impl Made {
    /// Its bytes copied, in memory of our own.
    fn copied(&self) -> Result<Vec<u8>, IdnFailure> {
        // SAFETY: libidn2 gave a C string on success, which lives until
        // freed in `drop`.
        let text = unsafe { CStr::from_ptr(self.0) }.to_bytes();
        let mut out = Vec::new();
        out.try_extend_from_slice(text)?;
        Ok(out)
    }
}

impl Drop for Made {
    fn drop(&mut self) {
        // SAFETY: a string libidn2 allocated, freed once, here; NULL is
        // its no-op.
        unsafe { idn2_free(self.0.cast()) };
    }
}

/// `text` with a NUL after it, for libidn2; a name with a NUL inside is
/// none it can convert.
fn terminated(text: &[u8]) -> Result<Vec<u8>, IdnFailure> {
    if text.contains(&0) {
        return Err(IdnFailure::Malformed);
    }
    let mut z = Vec::new();
    z.try_reserve_exact(text.len() + 1)
        .map_err(|_| IdnFailure::OutOfMemory)?;
    z.try_extend_from_slice(text)?;
    z.try_push(0)?;
    Ok(z)
}

/// What libidn2's answer `rc` with `made` gives.
fn answer(rc: c_int, made: Made) -> Result<Vec<u8>, IdnFailure> {
    match rc {
        OK if !made.0.is_null() => made.copied(),
        MALLOC => Err(IdnFailure::OutOfMemory),
        _ => Err(IdnFailure::Malformed),
    }
}

/// `name` looked up with `flags` (`IDN2_LOOKUP`, the locale's characters).
fn lookup(name: &CStr, flags: c_int) -> (c_int, Made) {
    let mut out = core::ptr::null_mut();
    // SAFETY: a C string in, and a pointer libidn2 sets to a string of
    // its own on success.
    let rc = unsafe { idn2_lookup_ul(name.as_ptr(), &raw mut out, flags) };
    (rc, Made(out))
}

impl Idn for Idn2 {
    fn to_ascii(&self, name: &[u8]) -> Result<Vec<u8>, IdnFailure> {
        // SAFETY: a C string libidn2 compares its own version with.
        if unsafe { idn2_check_version(WANTED.as_ptr()) }.is_null() {
            // C's `CURLE_NOT_BUILT_IN` for a library too old, which the
            // transfer reports as a malformed URL's all the same.
            return Err(IdnFailure::Malformed);
        }
        let z = terminated(name)?;
        let name = CStr::from_bytes_with_nul(&z).expect("one NUL, at the end");
        // IDNA 2008 non-transitional, then 2003's transitional where 2008
        // refuses the name (`idn_decode`).
        let (rc, made) = lookup(name, NFC_INPUT | NONTRANSITIONAL);
        if rc == OK {
            return answer(rc, made);
        }
        drop(made);
        let (rc, made) = lookup(name, TRANSITIONAL);
        answer(rc, made)
    }

    fn to_unicode(&self, ascii: &[u8]) -> Result<Vec<u8>, IdnFailure> {
        let z = terminated(ascii)?;
        let mut out = core::ptr::null_mut();
        // SAFETY: a C string in, and a pointer libidn2 sets to a string of
        // its own on success.
        let rc = unsafe { idn2_to_unicode_8z8z(z.as_ptr().cast(), &raw mut out, 0) };
        answer(rc, Made(out))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Names convert as C's build converts them (tests 165 and 1560), in
    /// a UTF-8 locale; a name that is no UTF-8, or has a NUL, does not;
    /// and punycode shows back in Unicode. The crate's one test: the
    /// locale it sets is the process's.
    #[test]
    fn names_convert_as_c_s_build_converts_them() {
        // SAFETY: a C string naming a locale; no other test runs to read
        // the locale while it changes.
        let set = unsafe { libc::setlocale(libc::LC_CTYPE, c"C.UTF-8".as_ptr()) };
        assert!(!set.is_null(), "the system has C.UTF-8");
        assert_eq!(
            IDN2.to_ascii("www.åäö.se".as_bytes()),
            Ok(b"www.xn--4cab6c.se".to_vec())
        );
        assert_eq!(
            IDN2.to_ascii("www.große.de".as_bytes()),
            Ok(b"www.xn--groe-xna.de".to_vec())
        );
        // Normalised first: a decomposed ä is the composed one's
        // (`IDN2_NFC_INPUT`).
        assert_eq!(
            IDN2.to_ascii("a\u{308}.test".as_bytes()),
            IDN2.to_ascii("\u{e4}.test".as_bytes())
        );
        assert_eq!(
            IDN2.to_ascii(b"invalid-utf8-\xe2\x90.local"),
            Err(IdnFailure::Malformed)
        );
        assert_eq!(IDN2.to_ascii(b"a\0b"), Err(IdnFailure::Malformed));
        assert_eq!(
            IDN2.to_unicode(b"www.xn--4cab6c.se"),
            Ok("www.åäö.se".as_bytes().to_vec())
        );
        assert!(version().starts_with("2."), "{}", version());
    }
}
