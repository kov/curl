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
use curl_core::version::{Feature, Library, Protocol, version, version_with_tls};

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
    crate::protocols::NAMES[p.index()]
}

static PROTOCOL_NAMES: OnceLock<CList<{ MAX_PROTOCOLS + 1 }>> = OnceLock::new();

/// Room for every feature C knows, and the NULL after them.
const MAX_FEATURES: usize = 64;

/// A feature's name and bit in `curl_version_info_data`.
fn c_feature(f: Feature) -> (&'static CStr, c_int) {
    match f {
        Feature::AltSvc => (c"alt-svc", crate::ffi::CURL_VERSION_ALTSVC),
        // A name alone, without a bit, as in C.
        Feature::AppleSecTrust => (c"AppleSecTrust", 0),
        Feature::AsynchDns => (c"AsynchDNS", crate::ffi::CURL_VERSION_ASYNCHDNS),
        Feature::Brotli => (c"brotli", crate::ffi::CURL_VERSION_BROTLI),
        Feature::Debug => (c"Debug", crate::ffi::CURL_VERSION_DEBUG),
        // A name alone, without a bit, as in C.
        Feature::Ech => (c"ECH", 0),
        Feature::GssApi => (c"GSS-API", crate::ffi::CURL_VERSION_GSSAPI),
        Feature::Hsts => (c"HSTS", crate::ffi::CURL_VERSION_HSTS),
        Feature::HttpsRr => (c"HTTPSRR", 0),
        Feature::Http2 => (c"HTTP2", crate::ffi::CURL_VERSION_HTTP2),
        Feature::Http3 => (c"HTTP3", crate::ffi::CURL_VERSION_HTTP3),
        Feature::HttpsProxy => (c"HTTPS-proxy", crate::ffi::CURL_VERSION_HTTPS_PROXY),
        // A name alone, without a bit, as in C.
        Feature::Httpsig => (c"HTTPSIG", 0),
        Feature::Idn => (c"IDN", crate::ffi::CURL_VERSION_IDN),
        Feature::Ipv6 => (c"IPv6", crate::ffi::CURL_VERSION_IPV6),
        Feature::Kerberos => (c"Kerberos", crate::ffi::CURL_VERSION_KERBEROS5),
        Feature::Largefile => (c"Largefile", crate::ffi::CURL_VERSION_LARGEFILE),
        Feature::Libz => (c"libz", crate::ffi::CURL_VERSION_LIBZ),
        // A name alone, without a bit, as in C.
        Feature::NativeCa => (c"NativeCA", 0),
        // A name alone, without a bit, as in C.
        Feature::ProxyHttp3 => (c"proxy-HTTP3", 0),
        Feature::Psl => (c"PSL", crate::ffi::CURL_VERSION_PSL),
        Feature::Spnego => (c"SPNEGO", crate::ffi::CURL_VERSION_SPNEGO),
        Feature::Ssl => (c"SSL", crate::ffi::CURL_VERSION_SSL),
        // A name alone, without a bit, as in C.
        Feature::SslsExport => (c"SSLS-EXPORT", 0),
        Feature::Sspi => (c"SSPI", crate::ffi::CURL_VERSION_SSPI),
        Feature::Threadsafe => (c"threadsafe", crate::ffi::CURL_VERSION_THREADSAFE),
        Feature::Unicode => (c"Unicode", crate::ffi::CURL_VERSION_UNICODE),
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
static ARES: OnceLock<CBuf<32>> = OnceLock::new();
static QUIC: OnceLock<CBuf<64>> = OnceLock::new();
static LIBSSH: OnceLock<CBuf<64>> = OnceLock::new();
static INFO: OnceLock<Data> = OnceLock::new();

/// The build's CA bundle and directory, as `curl_version_info` gives
/// them (C's `CURL_CA_BUNDLE` and `CURL_CA_PATH`), each NULL if none.
pub(crate) fn ca_defaults() -> (*const c_char, *const c_char) {
    let i = info();
    (i.cainfo, i.capath)
}

fn info() -> &'static curl_version_info_data {
    let v = version_with_tls(&crate::tlslib::TLS.support());
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
    let ssl = SSL.get_or_init(|| cbuf(format_args!("{}", crate::tlslib::version())));
    // The build's defaults, as C's `CURL_CA_BUNDLE` and `CURL_CA_PATH`.
    let ca = crate::tlslib::TLS.ca_defaults();
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
    let quic = crate::tlslib::quic().map(|q| QUIC.get_or_init(|| cbuf(format_args!("{q}"))));
    // Named, as C's `Curl_ssh_version` names it.
    let libssh = LIBSSH.get_or_init(|| {
        cbuf(format_args!(
            "{}/{}",
            curl_backends::ssh::NAME,
            curl_backends::ssh::version()
        ))
    });
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
                ares: if cfg!(feature = "threaded-resolver") {
                    ptr::null()
                } else {
                    ARES.get_or_init(|| cbuf(format_args!("{}", curl_backends::dns::version())))
                        .as_ptr()
                },
                ares_num: if cfg!(feature = "threaded-resolver") {
                    0
                } else {
                    curl_backends::dns::version_number() as _
                },
                libidn: curl_idn2::version_c().map_or(ptr::null(), CStr::as_ptr),
                iconv_ver_num: 0,
                libssh_version: libssh.as_ptr(),
                brotli_ver_num: curl_brotli::version_number(),
                brotli_version: brotli.as_ptr(),
                nghttp2_ver_num: curl_nghttp2::version_number(),
                nghttp2_version: curl_nghttp2::version_c().as_ptr(),
                quic_version: quic.map_or(ptr::null(), CBuf::as_ptr),
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
            let ssl = crate::tlslib::version();
            let zlib = Library("zlib", curl_zlib::version());
            let brotli = Library("brotli", curl_brotli::version());
            let zstd = Library("zstd", curl_zstd::version());
            let ares = Library("c-ares", curl_backends::dns::version());
            let idn = curl_idn2::Shown;
            let psl = Library("libpsl", curl_psl::version());
            let ssh = Library(curl_backends::ssh::NAME, curl_backends::ssh::version());
            let h2 = Library("nghttp2", curl_nghttp2::version());
            // A build without QUIC names no QUIC library.
            let h3 = crate::tlslib::quic();
            // Kerberos is SSPI's on Windows, which names no library.
            #[cfg(not(windows))]
            let gss = Some(Library(curl_gssapi::NAME, curl_gssapi::version()));
            #[cfg(windows)]
            let gss: Option<Library<&str>> = None;
            // Named by the library itself (`Curl_ldap_version`).
            let ldap = curl_ldap::version();
            // A build with the threaded resolver does not use c-ares.
            let ares = (!cfg!(feature = "threaded-resolver")).then_some(ares);
            let libraries: [Option<&dyn fmt::Display>; 12] = [
                Some(&ssl),
                Some(&zlib),
                Some(&brotli),
                Some(&zstd),
                ares.as_ref().map(|a| a as &dyn fmt::Display),
                Some(&idn),
                Some(&psl),
                Some(&ssh),
                Some(&h2),
                h3.as_ref().map(|h| h as &dyn fmt::Display),
                gss.as_ref().map(|g| g as &dyn std::fmt::Display),
                ldap.as_ref().map(|l| l as &dyn fmt::Display),
            ];
            let mut linked: [&dyn fmt::Display; 12] = [&""; 12];
            let mut n = 0;
            for library in libraries.into_iter().flatten() {
                linked[n] = library;
                n += 1;
            }
            let shown = &linked[..n];
            cbuf(format_args!("{}", version().components(shown)))
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
    /// The GSS-API library after a space: none on Windows, where Kerberos
    /// is SSPI's.
    #[cfg(any(
        feature = "openssl-tls",
        feature = "gnutls",
        feature = "mbedtls",
        feature = "wolfssl",
        feature = "rustls"
    ))]
    fn gss_shown() -> String {
        #[cfg(not(windows))]
        return format!(" {}/{}", curl_gssapi::NAME, curl_gssapi::version());
        #[cfg(windows)]
        return String::new();
    }

    /// The LDAP library after a space, as the version string has it:
    /// none where the build has none.
    #[cfg(any(
        feature = "openssl-tls",
        feature = "gnutls",
        feature = "mbedtls",
        feature = "wolfssl",
        feature = "rustls"
    ))]
    fn ldap_shown() -> String {
        let ldap = curl_ldap::version();
        ldap.map_or_else(String::new, |v| format!(" {v}"))
    }

    #[cfg(any(
        feature = "openssl-tls",
        feature = "gnutls",
        feature = "mbedtls",
        feature = "wolfssl",
        feature = "rustls"
    ))]
    fn ares_shown() -> String {
        if cfg!(feature = "threaded-resolver") {
            String::new()
        } else {
            format!(" c-ares/{}", curl_backends::dns::version())
        }
    }

    /// The QUIC libraries as C's build over them names them: ngtcp2 and
    /// nghttp3, or quiche.
    #[cfg(feature = "openssl")]
    fn quic_shown() -> String {
        format!(
            "ngtcp2/{} nghttp3/{}",
            curl_backends::curl_ngtcp2::ngtcp2_version(),
            curl_backends::curl_ngtcp2::nghttp3_version()
        )
    }
    #[cfg(feature = "quiche")]
    fn quic_shown() -> String {
        format!("quiche/{}", curl_backends::curl_quiche::quiche_version())
    }

    #[cfg(feature = "openssl-tls")]
    #[test]
    fn names_the_libraries_as_c() {
        // SAFETY: a static C string.
        let said = unsafe { CStr::from_ptr(curl_version()) }.to_str().unwrap();
        let want = format!(
            "libcurl/{} {} zlib/{} brotli/{} zstd/{}{} {} libpsl/{} {}/{} nghttp2/{} {}{}{}",
            version().version,
            curl_backends::curl_openssl::version(),
            curl_zlib::version(),
            curl_brotli::version(),
            curl_zstd::version(),
            ares_shown(),
            curl_idn2::Shown,
            curl_psl::version(),
            curl_backends::ssh::NAME,
            curl_backends::ssh::version(),
            curl_nghttp2::version(),
            quic_shown(),
            gss_shown(),
            ldap_shown()
        );
        assert_eq!(said, want);
        // SAFETY: as above.
        let info = unsafe { CStr::from_ptr(info().libz_version) }
            .to_str()
            .unwrap();
        assert!(said.contains(&format!(" zlib/{info} ")), "{said}");
    }

    /// With GnuTLS, mbedTLS or wolfSSL, the version string names it after
    /// libcurl, and the QUIC libraries after nghttp2 where the build has
    /// them, as `quic_version` does, as C's GnuTLS and wolfSSL builds over
    /// ngtcp2's crypto for them, and its mbedTLS build.
    #[cfg(any(
        feature = "gnutls",
        feature = "mbedtls",
        feature = "wolfssl",
        feature = "rustls"
    ))]
    #[test]
    fn names_the_libraries_as_c_s_gnutls_mbedtls_and_wolfssl_builds() {
        // SAFETY: a static C string.
        let said = unsafe { CStr::from_ptr(curl_version()) }.to_str().unwrap();
        let quic = crate::tlslib::quic().map(|q| q.to_string());
        assert_eq!(
            quic.is_some(),
            cfg!(any(feature = "gnutls", feature = "wolfssl"))
        );
        let want = format!(
            "libcurl/{} {} zlib/{} brotli/{} zstd/{}{} {} libpsl/{} {}/{} nghttp2/{}{}{}{}",
            version().version,
            crate::tlslib::version(),
            curl_zlib::version(),
            curl_brotli::version(),
            curl_zstd::version(),
            ares_shown(),
            curl_idn2::Shown,
            curl_psl::version(),
            curl_backends::ssh::NAME,
            curl_backends::ssh::version(),
            curl_nghttp2::version(),
            quic.as_ref().map_or_else(String::new, |q| format!(" {q}")),
            gss_shown(),
            ldap_shown()
        );
        assert_eq!(said, want);
        let named = if cfg!(feature = "gnutls") {
            " GnuTLS/3."
        } else if cfg!(feature = "wolfssl") {
            " wolfSSL/5."
        } else if cfg!(feature = "rustls") {
            " rustls-ffi/0.15.5/rustls/0.23."
        } else {
            " mbedTLS/3."
        };
        assert!(said.contains(named), "{said}");
        match quic {
            Some(q) => {
                // SAFETY: a static C string, not NULL where the build has
                // QUIC.
                let said = unsafe { CStr::from_ptr(info().quic_version) };
                assert_eq!(said.to_str(), Ok(q.as_str()));
            }
            None => assert!(info().quic_version.is_null()),
        }
    }

    /// Whether the build has an LDAP library.
    fn has_ldap() -> bool {
        curl_ldap::library().is_some()
    }

    /// The protocols the core reports reach the C struct as names.
    #[test]
    fn protocols_reach_the_c_struct() {
        let want: Vec<_> = version().protocols.iter().map(|p| p.name()).collect();
        assert_eq!(names(info().protocols), want);
        let mut all = vec![
            "dict", "file", "ftp", "ftps", "gopher", "gophers", "http", "https", "imap", "imaps",
            "ldap", "ldaps", "mqtt", "mqtts", "pop3", "pop3s", "rtsp", "scp", "sftp", "smtp",
            "smtps", "telnet", "tftp", "ws", "wss",
        ];
        // No LDAP where the LDAP crate has no library: the core's list
        // and the library linked agree.
        if !has_ldap() {
            all.retain(|p| !p.starts_with("ldap"));
        }
        assert_eq!(want, all);
    }

    /// HTTP/3's two libraries are named together in `quic_version`, as
    /// C names them.
    #[cfg(any(feature = "openssl", feature = "gnutls", feature = "wolfssl"))]
    #[test]
    fn quic_version_names_both_libraries() {
        // SAFETY: a static C string, never NULL.
        let quic = unsafe { CStr::from_ptr(info().quic_version) }
            .to_str()
            .unwrap();
        let want = format!(
            "ngtcp2/{} nghttp3/{}",
            curl_backends::curl_ngtcp2::ngtcp2_version(),
            curl_backends::curl_ngtcp2::nghttp3_version()
        );
        assert_eq!(quic, want);
    }

    /// quiche is named alone in `quic_version`, as C names it.
    #[cfg(feature = "quiche")]
    #[test]
    fn quic_version_names_quiche() {
        // SAFETY: a static C string, never NULL.
        let quic = unsafe { CStr::from_ptr(info().quic_version) }
            .to_str()
            .unwrap();
        assert_eq!(
            quic,
            format!("quiche/{}", curl_backends::curl_quiche::quiche_version())
        );
    }

    /// The features the core reports reach the C struct as bits and as
    /// names, the names NULL-terminated.
    #[test]
    fn features_reach_the_c_struct() {
        // OpenSSL's build has HTTP/3, the HTTP/3 proxy and message
        // signatures, GnuTLS's and wolfSSL's HTTP/3 and message
        // signatures, Schannel's neither.
        let quic = cfg!(any(
            feature = "openssl-tls",
            feature = "gnutls",
            feature = "wolfssl"
        ));
        let proxy_h3 = cfg!(feature = "openssl");
        let signs = cfg!(any(
            feature = "openssl-tls",
            feature = "gnutls",
            feature = "wolfssl"
        ));
        let info = info();
        let names = names(info.feature_names);
        let v = version_with_tls(&crate::tlslib::TLS.support());
        let want: Vec<_> = v.features.iter().map(|f| f.name()).collect();
        assert_eq!(names, want);
        let bits = v.features.iter().fold(0, |b, &f| b | c_feature(f).1);
        assert_eq!(info.features, bits);
        // The resolver and the debug hooks are the core's choice; the
        // core's tests pin them.
        let asynch = version().features.contains(&Feature::AsynchDns);
        let debug = version().features.contains(&Feature::Debug);
        let (listed, listed_bits): (Vec<_>, Vec<_>) = [
            (true, "alt-svc", ffi::CURL_VERSION_ALTSVC),
            // Apple's SecTrust verifies peers, with no bit of its own
            // (`USE_APPLE_SECTRUST`).
            (cfg!(feature = "apple-sectrust"), "AppleSecTrust", 0),
            (asynch, "AsynchDNS", ffi::CURL_VERSION_ASYNCHDNS),
            (true, "brotli", ffi::CURL_VERSION_BROTLI),
            (debug, "Debug", ffi::CURL_VERSION_DEBUG),
            // Where the TLS library has it, with no bit of its own
            // (`ech_present`).
            (crate::tlslib::TLS.support().ech, "ECH", 0),
            // SSPI in its place on Windows.
            (!cfg!(windows), "GSS-API", ffi::CURL_VERSION_GSSAPI),
            (true, "HSTS", ffi::CURL_VERSION_HSTS),
            (true, "HTTP2", ffi::CURL_VERSION_HTTP2),
            (quic, "HTTP3", ffi::CURL_VERSION_HTTP3),
            (true, "HTTPS-proxy", ffi::CURL_VERSION_HTTPS_PROXY),
            (signs, "HTTPSIG", 0),
            (true, "HTTPSRR", 0),
            (true, "IDN", ffi::CURL_VERSION_IDN),
            (true, "IPv6", ffi::CURL_VERSION_IPV6),
            (true, "Kerberos", ffi::CURL_VERSION_KERBEROS5),
            (true, "Largefile", ffi::CURL_VERSION_LARGEFILE),
            (true, "libz", ffi::CURL_VERSION_LIBZ),
            // The system's store as the default (`CURL_CA_NATIVE`), with
            // no bit of its own, unless SecTrust is claimed in its place.
            (
                cfg!(all(feature = "native-ca", not(feature = "apple-sectrust"))),
                "NativeCA",
                0,
            ),
            (proxy_h3, "proxy-HTTP3", 0),
            (true, "PSL", ffi::CURL_VERSION_PSL),
            (true, "SPNEGO", ffi::CURL_VERSION_SPNEGO),
            (true, "SSL", ffi::CURL_VERSION_SSL),
            (true, "SSLS-EXPORT", 0),
            (cfg!(windows), "SSPI", ffi::CURL_VERSION_SSPI),
            (true, "threadsafe", ffi::CURL_VERSION_THREADSAFE),
            // Windows' Unicode build (`ENABLE_UNICODE`).
            (
                cfg!(feature = "unicode"),
                "Unicode",
                ffi::CURL_VERSION_UNICODE,
            ),
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
