//! `curl_version` and `curl_version_info`.
//!
//! Both return pointers to static data, which the C API promises stays
//! valid for the life of the process. It is built once from
//! `curl_core::version()` into fixed buffers, so it never allocates.

#![allow(unsafe_code)]

use core::ffi::{CStr, c_char, c_int, c_uint};
use core::fmt::{self, Write};
use core::ptr;
use std::sync::OnceLock;

use curl_core::version::{Feature, version};

use crate::ffi::{self, CURLVERSION_NOW, CURLversion, curl_version_info_data};

/// A NUL-terminated string in a fixed buffer of `N` bytes.
struct CBuf<const N: usize> {
    bytes: [u8; N],
    len: usize,
}

impl<const N: usize> CBuf<N> {
    fn as_ptr(&self) -> *const c_char {
        self.bytes.as_ptr().cast()
    }
}

impl<const N: usize> Write for CBuf<N> {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        let end = self.len + s.len();
        // The last byte stays NUL.
        if s.contains('\0') || end >= N {
            return Err(fmt::Error);
        }
        self.bytes[self.len..end].copy_from_slice(s.as_bytes());
        self.len = end;
        Ok(())
    }
}

fn cbuf<const N: usize>(args: fmt::Arguments<'_>) -> CBuf<N> {
    let mut buf = CBuf {
        bytes: [0; N],
        len: 0,
    };
    buf.write_fmt(args)
        .expect("version strings fit their static buffers");
    buf
}

/// A NULL-terminated list of C strings.
struct CList<const N: usize>([*const c_char; N]);

// SAFETY: the pointers in a `CList` refer to static, never-written data, so
// sharing the list between threads shares only immutable data.
unsafe impl<const N: usize> Sync for CList<N> {}
// SAFETY: as for `Sync`; nothing in it is tied to a thread.
unsafe impl<const N: usize> Send for CList<N> {}

/// Empty until the core reports protocols.
static EMPTY: CList<1> = CList([ptr::null()]);

/// Room for every feature C knows, and the NULL after them.
const MAX_FEATURES: usize = 64;

/// A feature's name and bit in `curl_version_info_data`.
fn c_feature(f: Feature) -> (&'static CStr, c_int) {
    match f {
        #[cfg(feature = "debug-hooks")]
        Feature::Debug => (c"Debug", crate::ffi::CURL_VERSION_DEBUG),
    }
}

static FEATURE_NAMES: OnceLock<CList<{ MAX_FEATURES + 1 }>> = OnceLock::new();

/// The C struct, pointing into the statics around it.
struct Data(curl_version_info_data);

// SAFETY: every pointer in `Data` refers to a static that is never written
// once initialised; the struct itself is not written after it is built.
unsafe impl Sync for Data {}
// SAFETY: as for `Sync`; nothing in it is tied to a thread.
unsafe impl Send for Data {}

static COMPONENTS: OnceLock<CBuf<300>> = OnceLock::new();
static VERSION: OnceLock<CBuf<32>> = OnceLock::new();
static HOST: OnceLock<CBuf<32>> = OnceLock::new();
static INFO: OnceLock<Data> = OnceLock::new();

fn info() -> &'static curl_version_info_data {
    let v = version();
    assert!(v.protocols.is_empty(), "not translated yet");
    let feature_names = FEATURE_NAMES.get_or_init(|| {
        let mut names = CList([ptr::null(); MAX_FEATURES + 1]);
        assert!(v.features.len() <= MAX_FEATURES, "room for every feature");
        for (slot, &f) in names.0.iter_mut().zip(v.features) {
            *slot = c_feature(f).0.as_ptr();
        }
        names
    });
    let features = v.features.iter().fold(0, |bits, &f| bits | c_feature(f).1);
    let r = v.release;
    let version = VERSION.get_or_init(|| cbuf(format_args!("{}", v.version)));
    let host = HOST.get_or_init(|| cbuf(format_args!("{}", v.host)));
    &INFO
        .get_or_init(|| {
            Data(curl_version_info_data {
                age: CURLversion(CURLVERSION_NOW),
                version: version.as_ptr(),
                version_num: (c_uint::from(r.major) << 16)
                    | (c_uint::from(r.minor) << 8)
                    | c_uint::from(r.patch),
                host: host.as_ptr(),
                features,
                ssl_version: ptr::null(),
                ssl_version_num: 0,
                libz_version: ptr::null(),
                protocols: EMPTY.0.as_ptr(),
                ares: ptr::null(),
                ares_num: 0,
                libidn: ptr::null(),
                iconv_ver_num: 0,
                libssh_version: ptr::null(),
                brotli_ver_num: 0,
                brotli_version: ptr::null(),
                nghttp2_ver_num: 0,
                nghttp2_version: ptr::null(),
                quic_version: ptr::null(),
                cainfo: ptr::null(),
                capath: ptr::null(),
                zstd_ver_num: 0,
                zstd_version: ptr::null(),
                hyper_version: ptr::null(),
                gsasl_version: ptr::null(),
                feature_names: feature_names.0.as_ptr(),
                rtmp_version: ptr::null(),
            })
        })
        .0
}

#[unsafe(no_mangle)]
pub extern "C" fn curl_version() -> *mut c_char {
    COMPONENTS
        .get_or_init(|| cbuf(format_args!("{}", version().components())))
        .as_ptr()
        .cast_mut()
}
const _: ffi::proto::curl_version = curl_version;

/// The caller's `_stamp` is ignored: the answer always has the current
/// age, as in C.
#[unsafe(no_mangle)]
pub extern "C" fn curl_version_info(_stamp: CURLversion) -> *mut curl_version_info_data {
    ptr::from_ref(info()).cast_mut()
}
const _: ffi::proto::curl_version_info = curl_version_info;

#[cfg(test)]
mod tests {
    use super::*;

    /// The features the core reports reach the C struct as bits and as
    /// names, the names NULL-terminated.
    #[test]
    fn features_reach_the_c_struct() {
        let info = info();
        let mut names = Vec::new();
        for i in 0.. {
            // SAFETY: the list is NULL-terminated, and stops being read at
            // the NULL.
            let p = unsafe { info.feature_names.wrapping_add(i).read() };
            if p.is_null() {
                break;
            }
            // SAFETY: each entry is a static C string.
            names.push(unsafe { CStr::from_ptr(p) }.to_str().unwrap());
        }
        let want: Vec<_> = version().features.iter().map(|f| f.name()).collect();
        assert_eq!(names, want);
        let bits = version()
            .features
            .iter()
            .fold(0, |b, &f| b | c_feature(f).1);
        assert_eq!(info.features, bits);
        #[cfg(feature = "debug-hooks")]
        assert_eq!(
            (names.as_slice(), info.features),
            (&["Debug"][..], ffi::CURL_VERSION_DEBUG)
        );
    }
}
