//! The public suffix list from libpsl (`lib/psl.c`): the latest list the
//! system has (`psl_latest`), or the one built into the library if there
//! is none, loaded the first time it is asked.
//!
//! C loads it again once it is 72 hours old (`PSL_TTL`); this keeps it for
//! the life of the handle, which no test can tell apart.

#![allow(unsafe_code)]

use core::ffi::{c_char, c_int};
use core::ptr::NonNull;
use std::sync::OnceLock;

use curl_alloc::{OutOfMemory, try_box};
use curl_core::cookie::{PublicSuffixes, Suffixes};

/// A new list, for handles to share.
pub fn suffixes() -> Result<Suffixes, OutOfMemory> {
    Suffixes::new(try_box(List::new())?)
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
    fn psl_is_public_suffix(psl: *const PslCtx, domain: *const c_char) -> c_int;
    fn psl_is_cookie_domain_acceptable(
        psl: *const PslCtx,
        hostname: *const c_char,
        cookie_domain: *const c_char,
    ) -> c_int;
}

/// The list, loaded when first asked.
#[derive(Default)]
pub struct List {
    loaded: OnceLock<Option<Ctx>>,
}

/// A loaded list: the system's, which is freed with it, or the library's
/// own, which is not.
enum Ctx {
    Latest(NonNull<PslCtx>),
    Builtin(NonNull<PslCtx>),
}

impl Ctx {
    fn as_ptr(&self) -> *const PslCtx {
        match self {
            Ctx::Latest(p) | Ctx::Builtin(p) => p.as_ptr(),
        }
    }
}

// SAFETY: a context is only read once loaded, and libpsl's queries on
// one may run from several threads at once; it is freed only with the
// list, which no other thread then reaches.
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

impl List {
    pub fn new() -> List {
        List::default()
    }

    fn ctx(&self) -> Option<&Ctx> {
        self.loaded
            .get_or_init(|| {
                // SAFETY: NULL asks for the system's list; the result is a
                // new context or NULL.
                let latest = unsafe { psl_latest(core::ptr::null()) };
                if let Some(p) = NonNull::new(latest) {
                    return Some(Ctx::Latest(p));
                }
                // SAFETY: takes nothing; the result is static or NULL.
                let builtin = unsafe { psl_builtin() };
                NonNull::new(builtin.cast_mut()).map(Ctx::Builtin)
            })
            .as_ref()
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

impl PublicSuffixes for List {
    fn available(&self) -> bool {
        self.ctx().is_some()
    }

    fn is_public_suffix(&self, domain: &[u8]) -> bool {
        let (Some(ctx), Some(domain)) = (self.ctx(), c_name(domain)) else {
            // A name the list cannot be asked about is taken as one.
            return true;
        };
        // SAFETY: `ctx` is a live context and `domain` a C string, both
        // alive for the call.
        unsafe { psl_is_public_suffix(ctx.as_ptr(), domain.as_ptr().cast()) != 0 }
    }

    fn accepts(&self, host: &[u8], domain: &[u8]) -> bool {
        let (Some(ctx), Some(host), Some(domain)) = (self.ctx(), c_name(host), c_name(domain))
        else {
            return false;
        };
        // SAFETY: as above, for both names.
        unsafe {
            psl_is_cookie_domain_acceptable(
                ctx.as_ptr(),
                host.as_ptr().cast(),
                domain.as_ptr().cast(),
            ) != 0
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn answers_as_libpsl() {
        let list = List::new();
        assert!(list.available());
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

    /// Without a list every name is a suffix, and no cookie domain is
    /// accepted.
    #[test]
    fn without_a_list_nothing_is_accepted() {
        let none = List {
            loaded: OnceLock::from(None),
        };
        assert!(!none.available());
        assert!(none.is_public_suffix(b"example.com"));
        assert!(!none.accepts(b"www.example.com", b"example.com"));
    }
}
