//! The public suffix lists libpsl gives: the latest the system has
//! (`psl_latest`) and the one built into the library (`psl_builtin`). When
//! each is loaded and how long kept is the core's (`curl_core::psl`).

#![allow(unsafe_code)]

use core::ffi::{c_char, c_int};
use core::ptr::NonNull;

use curl_alloc::try_box;
use curl_core::cookie::{PublicSuffixes, Suffixes};
use curl_core::psl::SuffixLibrary;

/// libpsl, for a handle's libraries.
pub static LIBPSL: Libpsl = Libpsl;

/// Where lists come from: libpsl.
pub struct Libpsl;

impl SuffixLibrary for Libpsl {
    fn latest(&self) -> Option<Suffixes> {
        Ctx::latest().and_then(list)
    }

    fn builtin(&self) -> Option<Suffixes> {
        Ctx::builtin().and_then(list)
    }
}

/// `ctx`, as a list the core holds; for want of the memory, none, as
/// libpsl answers for want of its own.
fn list(ctx: Ctx) -> Option<Suffixes> {
    Suffixes::new(try_box(ctx).ok()?).ok()
}

/// The library's version, as `curl -V` names it (`psl_version`).
pub fn version() -> impl core::fmt::Display {
    // SAFETY: with 0, `psl_check_version_number` only returns the
    // library's version number.
    let n = unsafe { psl_check_version_number(0) };
    Version(n >> 16, (n >> 8) & 0xff, n & 0xff)
}

struct Version(c_int, c_int, c_int);

impl core::fmt::Display for Version {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}.{}.{}", self.0, self.1, self.2)
    }
}

/// libpsl's opaque context.
#[repr(C)]
struct PslCtx {
    _private: [u8; 0],
}

unsafe extern "C" {
    fn psl_latest(fname: *const c_char) -> *mut PslCtx;
    fn psl_builtin() -> *const PslCtx;
    fn psl_free(psl: *mut PslCtx);
    fn psl_check_version_number(version: c_int) -> c_int;
    fn psl_is_public_suffix(psl: *const PslCtx, domain: *const c_char) -> c_int;
    fn psl_is_cookie_domain_acceptable(
        psl: *const PslCtx,
        hostname: *const c_char,
        cookie_domain: *const c_char,
    ) -> c_int;
}

/// A loaded list: the system's, which is freed with it, or the library's
/// own, which is not.
enum Ctx {
    Latest(NonNull<PslCtx>),
    Builtin(NonNull<PslCtx>),
}

impl Ctx {
    fn latest() -> Option<Ctx> {
        // SAFETY: NULL asks for the system's list; the result is a new
        // context or NULL.
        let latest = unsafe { psl_latest(core::ptr::null()) };
        NonNull::new(latest).map(Ctx::Latest)
    }

    fn builtin() -> Option<Ctx> {
        // SAFETY: takes nothing; the result is static or NULL.
        let builtin = unsafe { psl_builtin() };
        NonNull::new(builtin.cast_mut()).map(Ctx::Builtin)
    }

    fn as_ptr(&self) -> *const PslCtx {
        match self {
            Ctx::Latest(p) | Ctx::Builtin(p) => p.as_ptr(),
        }
    }
}

// SAFETY: a context is only read once loaded, and libpsl's queries on
// one may run from several threads at once; it is freed only as the last
// holder of its list drops it, which no other thread then reaches.
unsafe impl Send for Ctx {}
// SAFETY: as for `Send`: shared, it is only read.
unsafe impl Sync for Ctx {}

impl Drop for Ctx {
    fn drop(&mut self) {
        if let Ctx::Latest(p) = self {
            // SAFETY: `p` came from `psl_latest`, and nothing uses it after
            // the list that owns it.
            unsafe { psl_free(p.as_ptr()) };
        }
    }
}

/// The longest name asked about, as C's buffers take it, and its zero
/// byte.
const NAME: usize = 256;

/// `name` with a zero byte after it, if it fits and holds none.
fn c_name(name: &[u8]) -> Option<[u8; NAME]> {
    if name.len() >= NAME || name.contains(&0) {
        return None;
    }
    let mut out = [0u8; NAME];
    out[..name.len()].copy_from_slice(name);
    Some(out)
}

impl PublicSuffixes for Ctx {
    fn is_public_suffix(&self, domain: &[u8]) -> bool {
        let Some(domain) = c_name(domain) else {
            // A name the list cannot be asked about is taken as one.
            return true;
        };
        // SAFETY: `self` is a live context and `domain` a C string, both
        // alive for the call.
        unsafe { psl_is_public_suffix(self.as_ptr(), domain.as_ptr().cast()) != 0 }
    }

    fn accepts(&self, host: &[u8], domain: &[u8]) -> bool {
        let (Some(host), Some(domain)) = (c_name(host), c_name(domain)) else {
            return false;
        };
        // SAFETY: as above, for both names.
        unsafe {
            psl_is_cookie_domain_acceptable(
                self.as_ptr(),
                host.as_ptr().cast(),
                domain.as_ptr().cast(),
            ) != 0
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::disallowed_macros)]

    use super::*;

    unsafe extern "C" {
        fn psl_get_version() -> *const c_char;
    }

    /// The version is the one libpsl says in words, before what it says
    /// of the libraries it uses: `0.21.5 (+libidn2/2.3.8)`.
    #[test]
    fn names_the_version_as_libpsl() {
        // SAFETY: no preconditions.
        let words = unsafe { psl_get_version() };
        // SAFETY: libpsl returns a static C string.
        let words = unsafe { core::ffi::CStr::from_ptr(words) }.to_bytes();
        let number = words.split(|&b| b == b' ').next().unwrap();
        assert_eq!(format!("{}", version()).as_bytes(), number);
    }

    #[test]
    fn answers_as_libpsl() {
        let list = Ctx::latest().or_else(Ctx::builtin).unwrap();
        assert!(list.is_public_suffix(b"com"));
        assert!(list.is_public_suffix(b"co.uk"));
        assert!(!list.is_public_suffix(b"example.com"));
        assert!(!list.accepts(b"x.com", b"com"));
        assert!(list.accepts(b"www.example.com", b"example.com"));
        assert!(list.accepts(b"localhost", b"localhost"));
        // What cannot be asked is refused.
        assert!(!list.accepts(b"a\0b", b"b"));
        assert!(list.is_public_suffix(&[b'a'; NAME]));
    }

    /// A name is asked about only if it fits C's buffer with its zero
    /// byte, and holds none of its own.
    #[test]
    fn names_end_in_one_zero_byte() {
        let longest = c_name(&[b'a'; NAME - 1]).unwrap();
        assert_eq!(longest[..NAME - 1], [b'a'; NAME - 1]);
        assert_eq!(longest[NAME - 1], 0);
        assert_eq!(c_name(b"example.com").unwrap()[..12], *b"example.com\0");
        assert_eq!(c_name(&[b'a'; NAME]), None);
        assert_eq!(c_name(b"a\0b"), None);
    }

    /// The library gives the system's list or its own, each a list that
    /// answers as libpsl's does, and the system's is freed with its last
    /// holder.
    #[test]
    fn the_library_gives_lists_that_answer() {
        let builtin = LIBPSL.builtin();
        assert!(builtin.is_some(), "this build's libpsl has one");
        for list in [LIBPSL.latest(), builtin].into_iter().flatten() {
            let held = list.clone();
            drop(list);
            assert_eq!(format!("{held:?}"), "Suffixes");
        }
    }
}
