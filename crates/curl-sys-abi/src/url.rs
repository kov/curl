//! The URL API, `curl_url` and its kin: a `CURLU *` is a core `Url` in
//! memory of its own.

#![allow(unsafe_code)]

use core::ffi::{CStr, c_char, c_int, c_uint};
use core::ptr::{self, NonNull};

use curl_alloc::try_box;
use curl_core::error::UrlErrorKind;
use curl_core::url::{GetOptions, ParseOptions, Part, SetOptions, Url};

use crate::error_codes::url_code;
use crate::ffi::{self, CURLU, CURLUPart, CURLUcode};
use crate::root;

/// The part `what` names, if any.
fn part(what: CURLUPart) -> Option<Part> {
    Some(match what {
        ffi::CURLUPART_URL => Part::Url,
        ffi::CURLUPART_SCHEME => Part::Scheme,
        ffi::CURLUPART_USER => Part::User,
        ffi::CURLUPART_PASSWORD => Part::Password,
        ffi::CURLUPART_OPTIONS => Part::Options,
        ffi::CURLUPART_HOST => Part::Host,
        ffi::CURLUPART_PORT => Part::Port,
        ffi::CURLUPART_PATH => Part::Path,
        ffi::CURLUPART_QUERY => Part::Query,
        ffi::CURLUPART_FRAGMENT => Part::Fragment,
        ffi::CURLUPART_ZONEID => Part::ZoneId,
        _ => return None,
    })
}

fn has(flags: c_uint, flag: c_int) -> bool {
    flags & flag as c_uint != 0
}

/// The `CURLU_*` flags as `curl_url_get` reads them; unknown bits are
/// ignored, as C ignores them.
pub(crate) fn get_options(flags: c_uint) -> GetOptions {
    GetOptions {
        default_port: has(flags, ffi::CURLU_DEFAULT_PORT),
        no_default_port: has(flags, ffi::CURLU_NO_DEFAULT_PORT),
        default_scheme: has(flags, ffi::CURLU_DEFAULT_SCHEME),
        url_decode: has(flags, ffi::CURLU_URLDECODE),
        url_encode: has(flags, ffi::CURLU_URLENCODE),
        get_empty: has(flags, ffi::CURLU_GET_EMPTY),
        no_guess_scheme: has(flags, ffi::CURLU_NO_GUESS_SCHEME),
        punycode: has(flags, ffi::CURLU_PUNYCODE),
        puny2idn: has(flags, ffi::CURLU_PUNY2IDN),
    }
}

/// The `CURLU_*` flags as `curl_url_set` reads them.
pub(crate) fn set_options(flags: c_uint) -> SetOptions {
    SetOptions {
        parse: ParseOptions {
            default_scheme: has(flags, ffi::CURLU_DEFAULT_SCHEME),
            guess_scheme: has(flags, ffi::CURLU_GUESS_SCHEME),
            non_support_scheme: has(flags, ffi::CURLU_NON_SUPPORT_SCHEME),
            no_authority: has(flags, ffi::CURLU_NO_AUTHORITY),
            path_as_is: has(flags, ffi::CURLU_PATH_AS_IS),
            disallow_user: has(flags, ffi::CURLU_DISALLOW_USER),
            allow_space: has(flags, ffi::CURLU_ALLOW_SPACE),
            url_encode: has(flags, ffi::CURLU_URLENCODE),
        },
        append_query: has(flags, ffi::CURLU_APPENDQUERY),
        get: get_options(flags),
    }
}

/// A `CURLU *` holding `url`, or NULL if out of memory.
fn boxed(url: Url) -> *mut CURLU {
    match try_box(url) {
        Ok(b) => Box::into_raw(b).cast(),
        Err(_) => ptr::null_mut(),
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn curl_url() -> *mut CURLU {
    boxed(Url::default())
}
const _: ffi::proto::curl_url = curl_url;

/// # Safety
///
/// `u` is NULL or a handle from `curl_url` or `curl_url_dup`, not used
/// again.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn curl_url_cleanup(u: *mut CURLU) {
    if !u.is_null() {
        // SAFETY: made by `boxed`, and the caller gives it up.
        drop(unsafe { Box::from_raw(u.cast::<Url>()) });
    }
}
const _: ffi::proto::curl_url_cleanup = curl_url_cleanup;

/// # Safety
///
/// `u` is NULL or a live handle.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn curl_url_dup(u: *const CURLU) -> *mut CURLU {
    // SAFETY: as the caller guarantees.
    let Some(u) = (unsafe { u.cast::<Url>().as_ref() }) else {
        return ptr::null_mut();
    };
    match u.try_clone() {
        Ok(copy) => boxed(copy),
        Err(_) => ptr::null_mut(),
    }
}
const _: ffi::proto::curl_url_dup = curl_url_dup;

/// # Safety
///
/// `u` is NULL or a live handle, not in use elsewhere for the call;
/// `content` is NULL or a C string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn curl_url_set(
    u: *mut CURLU,
    what: CURLUPart,
    content: *const c_char,
    flags: c_uint,
) -> CURLUcode {
    // SAFETY: as the caller guarantees.
    let Some(u) = (unsafe { u.cast::<Url>().as_mut() }) else {
        return ffi::CURLUE_BAD_HANDLE;
    };
    // SAFETY: as the caller guarantees.
    let value = NonNull::new(content.cast_mut()).map(|p| unsafe { CStr::from_ptr(p.as_ptr()) });
    let Some(what) = part(what) else {
        // C measures a value before it looks at the part.
        return match value {
            Some(v) if v.count_bytes() > curl_core::url::MAX_INPUT => ffi::CURLUE_MALFORMED_INPUT,
            _ => ffi::CURLUE_UNKNOWN_PART,
        };
    };
    match u.set(what, value.map(CStr::to_bytes), set_options(flags)) {
        Ok(()) => ffi::CURLUE_OK,
        Err(e) => url_code(e),
    }
}
const _: ffi::proto::curl_url_set = curl_url_set;

/// # Safety
///
/// `u` is NULL or a live handle; `part` is NULL or writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn curl_url_get(
    u: *const CURLU,
    what: CURLUPart,
    out: *mut *mut c_char,
    flags: c_uint,
) -> CURLUcode {
    // SAFETY: as the caller guarantees.
    let Some(u) = (unsafe { u.cast::<Url>().as_ref() }) else {
        return ffi::CURLUE_BAD_HANDLE;
    };
    let Some(out) = NonNull::new(out) else {
        return ffi::CURLUE_BAD_PARTPOINTER;
    };
    // SAFETY: as the caller guarantees.
    unsafe { out.write(ptr::null_mut()) };
    let Some(what) = part(what) else {
        return ffi::CURLUE_UNKNOWN_PART;
    };
    let text = match u.get(what, get_options(flags)) {
        Ok(text) => text,
        Err(e) => return url_code(e),
    };
    let s = root::allocator().c_string(&text);
    if s.is_null() {
        return url_code(UrlErrorKind::OutOfMemory);
    }
    // SAFETY: as above.
    unsafe { out.write(s) };
    ffi::CURLUE_OK
}
const _: ffi::proto::curl_url_get = curl_url_get;

#[cfg(test)]
mod tests {
    use super::*;

    /// What `curl_url_get` gives of `what`, or its error.
    fn get(u: *const CURLU, what: CURLUPart, flags: c_int) -> Result<String, CURLUcode> {
        // Not NULL, to see that it is set to NULL.
        let mut p: *mut c_char = NonNull::dangling().as_ptr();
        // SAFETY: a live handle and a place to write.
        let rc = unsafe { curl_url_get(u, what, &mut p, flags as c_uint) };
        if rc != ffi::CURLUE_OK {
            // Without a handle, C returns before it writes.
            assert!(
                p.is_null() || rc == ffi::CURLUE_BAD_HANDLE,
                "no part with an error"
            );
            return Err(rc);
        }
        // SAFETY: a C string this library made.
        let s = unsafe { CStr::from_ptr(p) }.to_string_lossy().into_owned();
        // SAFETY: handed to the caller, freed once.
        unsafe { root::curl_free(p.cast()) };
        Ok(s)
    }

    fn set(u: *mut CURLU, what: CURLUPart, value: Option<&CStr>, flags: c_int) -> CURLUcode {
        let p = value.map_or(ptr::null(), CStr::as_ptr);
        // SAFETY: a live handle and a C string or NULL.
        unsafe { curl_url_set(u, what, p, flags as c_uint) }
    }

    /// lib1560's `test_api_errors`, and a part out of range measured
    /// first, as C does.
    #[test]
    fn rejects_what_c_rejects() {
        let u = curl_url();
        assert_eq!(
            get(ptr::null(), ffi::CURLUPART_URL, 0),
            Err(ffi::CURLUE_BAD_HANDLE)
        );
        assert_eq!(
            set(
                ptr::null_mut(),
                ffi::CURLUPART_URL,
                Some(c"http://example.com"),
                0
            ),
            ffi::CURLUE_BAD_HANDLE
        );
        // SAFETY: NULL is allowed.
        assert!(unsafe { curl_url_dup(ptr::null()) }.is_null());
        // SAFETY: a live handle; NULL for the part pointer.
        let rc = unsafe { curl_url_get(u, ffi::CURLUPART_URL, ptr::null_mut(), 0) };
        assert_eq!(rc, ffi::CURLUE_BAD_PARTPOINTER);
        let unknown = CURLUPart(12345);
        assert_eq!(get(u, unknown, 0), Err(ffi::CURLUE_UNKNOWN_PART));
        assert_eq!(set(u, unknown, None, 0), ffi::CURLUE_UNKNOWN_PART);
        assert_eq!(set(u, unknown, Some(c"x"), 0), ffi::CURLUE_UNKNOWN_PART);
        let mut long = vec![b'a'; curl_core::url::MAX_INPUT + 1];
        long.push(0);
        let long = CStr::from_bytes_with_nul(&long).unwrap();
        assert_eq!(set(u, unknown, Some(long), 0), ffi::CURLUE_MALFORMED_INPUT);
        assert_eq!(
            set(u, ffi::CURLUPART_PATH, Some(long), 0),
            ffi::CURLUE_MALFORMED_INPUT
        );
        // SAFETY: made above, not used again.
        unsafe { curl_url_cleanup(u) };
        // SAFETY: NULL is allowed.
        unsafe { curl_url_cleanup(ptr::null_mut()) };
    }

    /// lib1560's `urldup`, and the flags reaching the core.
    #[test]
    fn copies_and_reads_back() {
        let u = curl_url();
        let url = c"http://user:pwd@[2a04:4e42:e00::347%25eth0]:80/path?query#fraggie";
        assert_eq!(
            set(u, ffi::CURLUPART_URL, Some(url), ffi::CURLU_GUESS_SCHEME),
            ffi::CURLUE_OK
        );
        // SAFETY: a live handle.
        let copy = unsafe { curl_url_dup(u) };
        assert_eq!(
            get(u, ffi::CURLUPART_URL, 0),
            get(copy, ffi::CURLUPART_URL, 0)
        );
        assert_eq!(get(copy, ffi::CURLUPART_ZONEID, 0).as_deref(), Ok("eth0"));
        assert_eq!(
            get(u, ffi::CURLUPART_URL, ffi::CURLU_NO_DEFAULT_PORT).as_deref(),
            Ok("http://user:pwd@[2a04:4e42:e00::347%25eth0]/path?query#fraggie")
        );
        assert_eq!(
            set(
                u,
                ffi::CURLUPART_QUERY,
                Some(c"a b"),
                ffi::CURLU_APPENDQUERY | ffi::CURLU_URLENCODE
            ),
            ffi::CURLUE_OK
        );
        assert_eq!(get(u, ffi::CURLUPART_QUERY, 0).as_deref(), Ok("query&a+b"));
        assert_eq!(
            set(
                u,
                ffi::CURLUPART_URL,
                Some(c"../x"),
                ffi::CURLU_DEFAULT_PORT
            ),
            ffi::CURLUE_OK
        );
        assert_eq!(
            get(u, ffi::CURLUPART_URL, 0).as_deref(),
            Ok("http://user:pwd@[2a04:4e42:e00::347%25eth0]:80/x")
        );
        assert_eq!(set(u, ffi::CURLUPART_URL, None, 0), ffi::CURLUE_OK);
        assert_eq!(get(u, ffi::CURLUPART_HOST, 0), Err(ffi::CURLUE_NO_HOST));
        assert_eq!(get(u, ffi::CURLUPART_PATH, 0).as_deref(), Ok("/"));
        // SAFETY: made above, not used again.
        unsafe { curl_url_cleanup(copy) };
        // SAFETY: as above.
        unsafe { curl_url_cleanup(u) };
    }
}
