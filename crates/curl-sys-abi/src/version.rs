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

use curl_core::tls::TlsBackend as _;
use curl_core::version::{Feature, Library, Protocol, version};

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

/// Room for every protocol C knows, and the NULL after them.
const MAX_PROTOCOLS: usize = 32;

/// A protocol's name, as `curl_version_info_data` lists it.
fn c_protocol(p: Protocol) -> &'static CStr {
    match p {
        Protocol::File => c"file",
        Protocol::Http => c"http",
        Protocol::Https => c"https",
    }
}

static PROTOCOL_NAMES: OnceLock<CList<{ MAX_PROTOCOLS + 1 }>> = OnceLock::new();

/// Room for every feature C knows, and the NULL after them.
const MAX_FEATURES: usize = 64;

/// A feature's name and bit in `curl_version_info_data`.
fn c_feature(f: Feature) -> (&'static CStr, c_int) {
    match f {
        Feature::AltSvc => (c"alt-svc", crate::ffi::CURL_VERSION_ALTSVC),
        Feature::AsynchDns => (c"AsynchDNS", crate::ffi::CURL_VERSION_ASYNCHDNS),
        Feature::Brotli => (c"brotli", crate::ffi::CURL_VERSION_BROTLI),
        #[cfg(feature = "debug-hooks")]
        Feature::Debug => (c"Debug", crate::ffi::CURL_VERSION_DEBUG),
        Feature::GssApi => (c"GSS-API", crate::ffi::CURL_VERSION_GSSAPI),
        Feature::Hsts => (c"HSTS", crate::ffi::CURL_VERSION_HSTS),
        Feature::Http2 => (c"HTTP2", crate::ffi::CURL_VERSION_HTTP2),
        Feature::Http3 => (c"HTTP3", crate::ffi::CURL_VERSION_HTTP3),
        Feature::HttpsProxy => (c"HTTPS-proxy", crate::ffi::CURL_VERSION_HTTPS_PROXY),
        // A name alone, without a bit, as in C.
        Feature::Httpsig => (c"HTTPSIG", 0),
        Feature::Idn => (c"IDN", crate::ffi::CURL_VERSION_IDN),
        Feature::Ipv6 => (c"IPv6", crate::ffi::CURL_VERSION_IPV6),
        Feature::Kerberos => (c"Kerberos", crate::ffi::CURL_VERSION_KERBEROS5),
        Feature::Libz => (c"libz", crate::ffi::CURL_VERSION_LIBZ),
        // A name alone, without a bit, as in C.
        Feature::ProxyHttp3 => (c"proxy-HTTP3", 0),
        Feature::Psl => (c"PSL", crate::ffi::CURL_VERSION_PSL),
        Feature::Spnego => (c"SPNEGO", crate::ffi::CURL_VERSION_SPNEGO),
        Feature::Ssl => (c"SSL", crate::ffi::CURL_VERSION_SSL),
        Feature::Threadsafe => (c"threadsafe", crate::ffi::CURL_VERSION_THREADSAFE),
        Feature::UnixSockets => (c"UnixSockets", crate::ffi::CURL_VERSION_UNIX_SOCKETS),
        Feature::Zstd => (c"zstd", crate::ffi::CURL_VERSION_ZSTD),
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
static SSL: OnceLock<CBuf<200>> = OnceLock::new();
static CAINFO: OnceLock<CBuf<4096>> = OnceLock::new();
static CAPATH: OnceLock<CBuf<4096>> = OnceLock::new();
static LIBZ: OnceLock<CBuf<32>> = OnceLock::new();
static BROTLI: OnceLock<CBuf<32>> = OnceLock::new();
static ZSTD: OnceLock<CBuf<32>> = OnceLock::new();
static QUIC: OnceLock<CBuf<64>> = OnceLock::new();
static INFO: OnceLock<Data> = OnceLock::new();

/// The build's CA bundle and directory, as `curl_version_info` gives
/// them (C's `CURL_CA_BUNDLE` and `CURL_CA_PATH`), each NULL if none.
pub(crate) fn ca_defaults() -> (*const c_char, *const c_char) {
    let i = info();
    (i.cainfo, i.capath)
}

fn info() -> &'static curl_version_info_data {
    let v = version();
    let protocol_names = PROTOCOL_NAMES.get_or_init(|| {
        let mut names = CList([ptr::null(); MAX_PROTOCOLS + 1]);
        assert!(
            v.protocols.len() <= MAX_PROTOCOLS,
            "room for every protocol"
        );
        for (slot, &p) in names.0.iter_mut().zip(v.protocols) {
            *slot = c_protocol(p).as_ptr();
        }
        names
    });
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
    let ssl = SSL.get_or_init(|| cbuf(format_args!("{}", curl_openssl::version())));
    // The build's defaults, as C's `CURL_CA_BUNDLE` and `CURL_CA_PATH`.
    let ca = curl_openssl::OPENSSL.ca_defaults();
    let cainfo = ca
        .file
        .map(|f| CAINFO.get_or_init(|| cbuf(format_args!("{f}"))));
    let capath = ca
        .path
        .map(|p| CAPATH.get_or_init(|| cbuf(format_args!("{p}"))));
    let libz = LIBZ.get_or_init(|| cbuf(format_args!("{}", curl_zlib::version())));
    // Named, as C's `brotli_version` names it.
    let brotli = BROTLI.get_or_init(|| cbuf(format_args!("brotli/{}", curl_brotli::version())));
    let zstd = ZSTD.get_or_init(|| cbuf(format_args!("zstd/{}", curl_zstd::version())));
    let quic = QUIC.get_or_init(|| cbuf(format_args!("{}", curl_ngtcp2::version())));
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
                ssl_version: ssl.as_ptr(),
                // Kept at zero, as C keeps it.
                ssl_version_num: 0,
                libz_version: libz.as_ptr(),
                protocols: protocol_names.0.as_ptr(),
                ares: ptr::null(),
                ares_num: 0,
                libidn: curl_idn2::version_c().as_ptr(),
                iconv_ver_num: 0,
                libssh_version: ptr::null(),
                brotli_ver_num: curl_brotli::version_number(),
                brotli_version: brotli.as_ptr(),
                nghttp2_ver_num: curl_nghttp2::version_number(),
                nghttp2_version: curl_nghttp2::version_c().as_ptr(),
                quic_version: quic.as_ptr(),
                cainfo: cainfo.map_or(ptr::null(), CBuf::as_ptr),
                capath: capath.map_or(ptr::null(), CBuf::as_ptr),
                zstd_ver_num: curl_zstd::version_number(),
                zstd_version: zstd.as_ptr(),
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
        .get_or_init(|| {
            // The libraries linked in, in C's order.
            let ssl = curl_openssl::version();
            let zlib = Library("zlib", curl_zlib::version());
            let brotli = Library("brotli", curl_brotli::version());
            let zstd = Library("zstd", curl_zstd::version());
            let idn = Library("libidn2", curl_idn2::version());
            let psl = Library("libpsl", curl_psl::version());
            let h2 = Library("nghttp2", curl_nghttp2::version());
            let h3 = curl_ngtcp2::version();
            let gss = Library("mit-krb5", curl_gssapi::version());
            let libraries: [&dyn fmt::Display; 9] =
                [&ssl, &zlib, &brotli, &zstd, &idn, &psl, &h2, &h3, &gss];
            cbuf(format_args!("{}", version().components(&libraries)))
        })
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

    /// The names in a NULL-terminated list of C strings.
    fn names(list: *const *const c_char) -> Vec<&'static str> {
        let mut names = Vec::new();
        for i in 0.. {
            // SAFETY: the list is NULL-terminated, and stops being read at
            // the NULL.
            let p = unsafe { list.wrapping_add(i).read() };
            if p.is_null() {
                break;
            }
            // SAFETY: each entry is a static C string.
            names.push(unsafe { CStr::from_ptr(p) }.to_str().unwrap());
        }
        names
    }

    /// `curl_version` lists the libraries linked in after libcurl, in
    /// C's order and words, each version as the library says it.
    #[test]
    fn names_the_libraries_as_c() {
        // SAFETY: a static C string.
        let said = unsafe { CStr::from_ptr(curl_version()) }.to_str().unwrap();
        let want = format!(
            "libcurl/{} {} zlib/{} brotli/{} zstd/{} libidn2/{} libpsl/{} nghttp2/{} ngtcp2/{} nghttp3/{} mit-krb5/{}",
            version().version,
            curl_openssl::version(),
            curl_zlib::version(),
            curl_brotli::version(),
            curl_zstd::version(),
            curl_idn2::version(),
            curl_psl::version(),
            curl_nghttp2::version(),
            curl_ngtcp2::ngtcp2_version(),
            curl_ngtcp2::nghttp3_version(),
            curl_gssapi::version()
        );
        assert_eq!(said, want);
        // SAFETY: as above.
        let info = unsafe { CStr::from_ptr(info().libz_version) }
            .to_str()
            .unwrap();
        assert!(said.contains(&format!(" zlib/{info} ")), "{said}");
    }

    /// The protocols the core reports reach the C struct as names.
    #[test]
    fn protocols_reach_the_c_struct() {
        let want: Vec<_> = version().protocols.iter().map(|p| p.name()).collect();
        assert_eq!(names(info().protocols), want);
        assert_eq!(want, ["file", "http", "https"]);
    }

    /// HTTP/3's two libraries are named together in `quic_version`, as
    /// C names them.
    #[test]
    fn quic_version_names_both_libraries() {
        // SAFETY: a static C string, never NULL.
        let quic = unsafe { CStr::from_ptr(info().quic_version) }
            .to_str()
            .unwrap();
        let want = format!(
            "ngtcp2/{} nghttp3/{}",
            curl_ngtcp2::ngtcp2_version(),
            curl_ngtcp2::nghttp3_version()
        );
        assert_eq!(quic, want);
    }

    /// The features the core reports reach the C struct as bits and as
    /// names, the names NULL-terminated.
    #[test]
    fn features_reach_the_c_struct() {
        let info = info();
        let names = names(info.feature_names);
        let want: Vec<_> = version().features.iter().map(|f| f.name()).collect();
        assert_eq!(names, want);
        let bits = version()
            .features
            .iter()
            .fold(0, |b, &f| b | c_feature(f).1);
        assert_eq!(info.features, bits);
        // The resolver is the core's choice; the core's tests pin it.
        let asynch = version().features.contains(&Feature::AsynchDns);
        let (listed, listed_bits): (Vec<_>, Vec<_>) = [
            (true, "alt-svc", ffi::CURL_VERSION_ALTSVC),
            (asynch, "AsynchDNS", ffi::CURL_VERSION_ASYNCHDNS),
            (true, "brotli", ffi::CURL_VERSION_BROTLI),
            (
                cfg!(feature = "debug-hooks"),
                "Debug",
                ffi::CURL_VERSION_DEBUG,
            ),
            (true, "GSS-API", ffi::CURL_VERSION_GSSAPI),
            (true, "HSTS", ffi::CURL_VERSION_HSTS),
            (true, "HTTP2", ffi::CURL_VERSION_HTTP2),
            (true, "HTTP3", ffi::CURL_VERSION_HTTP3),
            (true, "HTTPS-proxy", ffi::CURL_VERSION_HTTPS_PROXY),
            (true, "HTTPSIG", 0),
            (true, "IDN", ffi::CURL_VERSION_IDN),
            (true, "IPv6", ffi::CURL_VERSION_IPV6),
            (true, "Kerberos", ffi::CURL_VERSION_KERBEROS5),
            (true, "libz", ffi::CURL_VERSION_LIBZ),
            (true, "proxy-HTTP3", 0),
            (true, "PSL", ffi::CURL_VERSION_PSL),
            (true, "SPNEGO", ffi::CURL_VERSION_SPNEGO),
            (true, "SSL", ffi::CURL_VERSION_SSL),
            (true, "threadsafe", ffi::CURL_VERSION_THREADSAFE),
            (true, "UnixSockets", ffi::CURL_VERSION_UNIX_SOCKETS),
            (true, "zstd", ffi::CURL_VERSION_ZSTD),
        ]
        .into_iter()
        .filter(|&(claimed, _, _)| claimed)
        .map(|(_, name, bit)| (name, bit))
        .unzip();
        assert_eq!(
            (names.as_slice(), info.features),
            (&listed[..], listed_bits.iter().fold(0, |b, &bit| b | bit))
        );
    }
}
