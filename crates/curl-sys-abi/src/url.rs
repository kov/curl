//! The URL API, `curl_url` and its kin: a `CURLU *` is a core
//! `SharedUrl` held as its bare pointer, which `CURLOPT_CURLU` names and
//! a transfer reads as it starts.

#![allow(unsafe_code)]

use core::ffi::{CStr, c_char, c_int, c_uint};
use core::mem::ManuallyDrop;
use core::ptr::{self, NonNull};

use curl_alloc::{OutOfMemory, TryArc};
use curl_core::url::{
    GetOptions, ParseOptions, Part, SetOptions, SharedUrl, Url, UrlCell, UrlSink,
};

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

/// A `CURLU *` holding `url`, or NULL if out of memory: the shared URL's
/// own pointer, so that a handle costs its one block, as in C.
fn boxed(url: Url) -> *mut CURLU {
    match SharedUrl::new(url) {
        Ok(shared) => TryArc::into_raw(shared.into_arc()).as_ptr().cast(),
        Err(_) => ptr::null_mut(),
    }
}

/// The URL `u` points to, if any, lent: not dropped, so the handle stays
/// the application's. Clone it to keep it.
///
/// # Safety
///
/// `u` is NULL or a live handle from `boxed`, live for as long as the
/// result is used.
pub(crate) unsafe fn shared(u: *const CURLU) -> Option<ManuallyDrop<SharedUrl>> {
    let raw = NonNull::new(u.cast_mut())?;
    // SAFETY: `boxed` made it with `into_raw` of this type; as it is never
    // dropped, the application's handle is not taken from it.
    let arc = unsafe { TryArc::from_raw(raw.cast()) };
    Some(ManuallyDrop::new(SharedUrl::from_arc(arc)))
}

/// A C string the application frees with `curl_free`, written in place:
/// as long as asked for, with room for its terminating zero.
struct CText {
    start: *mut u8,
    room: usize,
    len: usize,
}

impl CText {
    const fn new() -> CText {
        CText {
            start: ptr::null_mut(),
            room: 0,
            len: 0,
        }
    }

    /// The string, terminated, the caller's to hand over.
    fn finish(self) -> *mut c_char {
        let text = ManuallyDrop::new(self);
        assert!(!text.start.is_null(), "a part is always asked room for");
        // `start` is a block of `room + 1` bytes and `write` keeps `len` at
        // most `room`, so the last byte written is within it.
        let end = text.start.wrapping_add(text.len);
        // SAFETY: as above.
        unsafe { end.write(0) };
        text.start.cast()
    }
}

impl UrlSink for CText {
    fn reserve(&mut self, len: usize) -> Result<(), OutOfMemory> {
        assert!(self.start.is_null(), "room is asked for once");
        let start = if len == 0 {
            // As C does: an empty result is a strdup of "".
            // SAFETY: the literal is NUL-terminated.
            unsafe { root::allocator().strdup(c"".as_ptr()) }.cast::<u8>()
        } else {
            let size = len.checked_add(1).ok_or(OutOfMemory)?;
            root::allocator().malloc(size).cast::<u8>()
        };
        if start.is_null() {
            return Err(OutOfMemory);
        }
        self.start = start;
        self.room = len;
        Ok(())
    }

    fn write(&mut self, bytes: &[u8]) -> Result<(), OutOfMemory> {
        assert!(bytes.len() <= self.room - self.len, "more than room asked");
        let to = self.start.wrapping_add(self.len);
        // SAFETY: `start` is a block of `room + 1` bytes, of which the
        // `bytes.len()` after `len` were just checked to be there; `bytes`
        // is memory of the caller's, never this fresh block.
        unsafe { ptr::copy_nonoverlapping(bytes.as_ptr(), to, bytes.len()) };
        self.len += bytes.len();
        Ok(())
    }
}

impl Drop for CText {
    fn drop(&mut self) {
        if !self.start.is_null() {
            // SAFETY: the allocator's block, not handed over: `finish` does
            // not drop.
            unsafe { root::allocator().free(self.start.cast()) };
        }
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
    if let Some(u) = NonNull::new(u) {
        // SAFETY: made by `boxed`, and the caller gives it up.
        drop(unsafe { TryArc::<UrlCell>::from_raw(u.cast()) });
    }
}
const _: ffi::proto::curl_url_cleanup = curl_url_cleanup;

/// # Safety
///
/// `u` is NULL or a live handle.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn curl_url_dup(u: *const CURLU) -> *mut CURLU {
    // SAFETY: as the caller guarantees.
    let Some(u) = (unsafe { shared(u) }) else {
        return ptr::null_mut();
    };
    match u.with(Url::try_clone) {
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
    let Some(u) = (unsafe { shared(u) }) else {
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
    match u.update(|u| u.set(what, value.map(CStr::to_bytes), set_options(flags))) {
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
    let Some(u) = (unsafe { shared(u) }) else {
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
    let mut text = CText::new();
    let idn = Some(crate::easy::IDN);
    if let Err(e) = u.with(|u| u.write_part(what, get_options(flags), idn, &mut text)) {
        return url_code(e);
    }
    // SAFETY: as above.
    unsafe { out.write(text.finish()) };
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

    /// Each part is named by its number, to set and to get.
    #[test]
    fn parts_are_named_as_in_c() {
        let u = curl_url();
        let url = c"http://user:pwd@host:8080/path?query#frag";
        assert_eq!(set(u, ffi::CURLUPART_URL, Some(url), 0), ffi::CURLUE_OK);
        for (part, want) in [
            (ffi::CURLUPART_SCHEME, Ok("http")),
            (ffi::CURLUPART_USER, Ok("user")),
            (ffi::CURLUPART_PASSWORD, Ok("pwd")),
            (ffi::CURLUPART_OPTIONS, Err(ffi::CURLUE_NO_OPTIONS)),
            (ffi::CURLUPART_HOST, Ok("host")),
            (ffi::CURLUPART_PORT, Ok("8080")),
            (ffi::CURLUPART_PATH, Ok("/path")),
            (ffi::CURLUPART_QUERY, Ok("query")),
            (ffi::CURLUPART_FRAGMENT, Ok("frag")),
        ] {
            assert_eq!(
                get(u, part, 0).as_deref().map_err(|e| *e),
                want,
                "{}",
                part.0
            );
        }
        for (part, value) in [
            (ffi::CURLUPART_SCHEME, c"https"),
            (ffi::CURLUPART_USER, c"u2"),
            (ffi::CURLUPART_PASSWORD, c"p2"),
            (ffi::CURLUPART_OPTIONS, c"o2"),
            (ffi::CURLUPART_PORT, c"81"),
            (ffi::CURLUPART_FRAGMENT, c"f2"),
        ] {
            assert_eq!(set(u, part, Some(value), 0), ffi::CURLUE_OK, "{}", part.0);
            assert_eq!(
                get(u, part, 0).as_deref(),
                Ok(value.to_str().unwrap()),
                "{}",
                part.0
            );
        }
        // SAFETY: made above, not used again.
        unsafe { curl_url_cleanup(u) };
    }

    /// What the calls cost in Rust's allocator, on which test 1560's limit
    /// on allocations rests: a handle its one block, a part and a whole URL
    /// nothing on the way to the application's block, each part held one,
    /// and the port's digits none.
    #[cfg(feature = "debug-hooks")]
    #[test]
    fn calls_cost_what_c_s_do() {
        use curl_alloc::track::count_allocations;
        let (u, made) = count_allocations(|| curl_url());
        assert_eq!(made, 1, "a handle");
        let url = c"http://user:pw@host:8080/path?q#f";
        let (rc, made) = count_allocations(|| set(u, ffi::CURLUPART_URL, Some(url), 0));
        assert_eq!(rc, ffi::CURLUE_OK);
        assert_eq!(
            made, 7,
            "scheme, user, password, host, path, query, fragment"
        );
        let mut p: *mut c_char = ptr::null_mut();
        for what in [ffi::CURLUPART_HOST, ffi::CURLUPART_URL] {
            // SAFETY: a live handle and a place to write.
            let (rc, made) = count_allocations(|| unsafe { curl_url_get(u, what, &mut p, 0) });
            assert_eq!(rc, ffi::CURLUE_OK);
            assert_eq!(made, 0, "part {}", what.0);
            // SAFETY: handed to the caller, freed once.
            unsafe { root::curl_free(p.cast()) };
        }
        // SAFETY: made above, not used again.
        unsafe { curl_url_cleanup(u) };
    }

    /// The application's block is asked for once and holds what is written:
    /// a host that encoding makes much longer.
    #[test]
    fn a_whole_url_fits_the_room_it_asks_for() {
        let u = curl_url();
        let url = c"http://\xc3\xa4\xc3\xa4\xc3\xa4\xc3\xa4\xc3\xa4\xc3\xa4\xc3\xa4\xc3\xa4\xc3\xa4\xc3\xa4\xc3\xa4\xc3\xa4\xc3\xa4\xc3\xa4\xc3\xa4\xc3\xa4/";
        assert_eq!(set(u, ffi::CURLUPART_URL, Some(url), 0), ffi::CURLUE_OK);
        let encoded = "%C3%A4".repeat(16);
        assert_eq!(
            get(u, ffi::CURLUPART_URL, ffi::CURLU_URLENCODE).as_deref(),
            Ok(format!("http://{encoded}/").as_str())
        );
        // SAFETY: made above, not used again.
        unsafe { curl_url_cleanup(u) };
    }

    /// A URL past the limit is refused, and nothing is handed over.
    #[test]
    #[cfg_attr(miri, ignore = "eight megabytes, byte by byte")]
    fn a_whole_url_past_the_limit_is_refused() {
        let u = curl_url();
        let url = c"http://host/";
        assert_eq!(set(u, ffi::CURLUPART_URL, Some(url), 0), ffi::CURLUE_OK);
        let mut path = vec![b'/'];
        path.resize(curl_core::url::MAX_INPUT - 1, b'a');
        path.push(0);
        let path = CStr::from_bytes_with_nul(&path).unwrap();
        assert_eq!(set(u, ffi::CURLUPART_PATH, Some(path), 0), ffi::CURLUE_OK);
        assert_eq!(get(u, ffi::CURLUPART_URL, 0), Err(ffi::CURLUE_TOO_LARGE));
        // SAFETY: made above, not used again.
        unsafe { curl_url_cleanup(u) };
    }

    /// A block not handed over is freed: Miri's leak check is what sees it.
    #[test]
    fn text_not_finished_is_freed() {
        let mut text = CText::new();
        text.reserve(3).unwrap();
        text.write(b"abc").unwrap();
        drop(text);
        let mut text = CText::new();
        text.reserve(3).unwrap();
        text.write(b"abc").unwrap();
        let p = text.finish();
        // SAFETY: a C string just terminated.
        assert_eq!(unsafe { CStr::from_ptr(p) }, c"abc");
        // SAFETY: handed to the caller, freed once.
        unsafe { root::curl_free(p.cast()) };
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
