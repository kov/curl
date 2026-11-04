//! What this build of the library is and can do.

use std::fmt;

mod curlver {
    include!(concat!(env!("OUT_DIR"), "/curlver.rs"));
}

/// A release number.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Release {
    pub major: u8,
    pub minor: u8,
    pub patch: u8,
}

/// An optional capability of the build.
///
/// Each variant exists once the capability is implemented; a build reports
/// only what it can do.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Feature {
    /// Names are resolved while the transfer goes on, by the threaded
    /// resolver's pool of threads, which C counts as asynchronous: claimed
    /// by a build with the `threaded-resolver` feature.
    AsynchDns,
    /// Alternative services: an origin's alternatives a server names are
    /// kept, from and to a file, and connected to in its place.
    AltSvc,
    /// A peer the TLS library cannot verify is verified by Apple's
    /// SecTrust against the system's trust settings (`USE_APPLE_SECTRUST`).
    AppleSecTrust,
    /// The `br` content coding is undone by brotli, which the tool and the
    /// C ABI give every handle.
    Brotli,
    /// A debug build, for the test suite: never for production. Listed
    /// only by a build with the `debug-hooks` feature.
    Debug,
    /// GSS-API, by MIT krb5, which the tool and the C ABI give every
    /// handle.
    GssApi,
    /// Strict Transport Security: hosts a server says to reach only over
    /// HTTPS are, from a file, the application or the server's word.
    Hsts,
    /// HTTPS records: asked for alongside an `https` origin's addresses,
    /// the versions they name tried first.
    HttpsRr,
    /// HTTP/2, by nghttp2, which the tool and the C ABI give every handle.
    Http2,
    /// HTTP/3 over QUIC, by ngtcp2 and nghttp3, which the tool and the C
    /// ABI give every handle.
    Http3,
    /// HTTPS proxies: TLS to the proxy, and TLS in TLS to an `https`
    /// origin through one, by the TLS library `Ssl` names.
    HttpsProxy,
    /// HTTP message signatures (RFC 9421), though only with HMAC-SHA256.
    Httpsig,
    /// Host names in Unicode are looked up by their punycode form, by
    /// libidn2, which the tool and the C ABI give every handle.
    Idn,
    /// Connections over IPv6, and its addresses in URLs.
    Ipv6,
    /// Kerberos 5 by GSS-API, as SOCKS5's GSS-API method uses it.
    Kerberos,
    /// Files, sizes and offsets past 2 GiB: every one is 64 bits (C's
    /// `curl_off_t` wider than 32).
    Largefile,
    /// The `deflate` and `gzip` content codings are undone by zlib, which
    /// the tool and the C ABI give every handle.
    Libz,
    /// HTTP/3 proxies: a tunnel through one is a stream of a QUIC
    /// connection to it (C's `USE_PROXY_HTTP3`).
    ProxyHttp3,
    /// Cookies' domains are checked against libpsl's public suffixes,
    /// which the tool and the C ABI give every handle.
    Psl,
    /// HTTP Negotiate by GSS-API, with the origin and with a proxy.
    Spnego,
    /// TLS, by OpenSSL, which the tool and the C ABI give every handle.
    Ssl,
    /// TLS sessions go in and out of the cache (`curl_easy_ssls_import`).
    SslsExport,
    /// Nothing the library keeps is process-wide: handles may be made, and
    /// the C ABI initialised, from several threads at once (C's
    /// `threadsafe`, its global initialisation under a lock).
    Threadsafe,
    /// Connections over Unix sockets, by path or abstract name.
    UnixSockets,
    /// The `zstd` content coding is undone by zstd, which the tool and the
    /// C ABI give every handle.
    Zstd,
}

impl Feature {
    /// The name `curl -V` lists it under.
    pub fn name(self) -> &'static str {
        match self {
            Feature::AltSvc => "alt-svc",
            Feature::AppleSecTrust => "AppleSecTrust",
            Feature::AsynchDns => "AsynchDNS",
            Feature::Brotli => "brotli",
            Feature::Debug => "Debug",
            Feature::GssApi => "GSS-API",
            Feature::Hsts => "HSTS",
            Feature::HttpsRr => "HTTPSRR",
            Feature::Http2 => "HTTP2",
            Feature::Http3 => "HTTP3",
            Feature::HttpsProxy => "HTTPS-proxy",
            Feature::Httpsig => "HTTPSIG",
            Feature::Idn => "IDN",
            Feature::Ipv6 => "IPv6",
            Feature::Kerberos => "Kerberos",
            Feature::Largefile => "Largefile",
            Feature::Libz => "libz",
            Feature::ProxyHttp3 => "proxy-HTTP3",
            Feature::Psl => "PSL",
            Feature::Spnego => "SPNEGO",
            Feature::Ssl => "SSL",
            Feature::SslsExport => "SSLS-EXPORT",
            Feature::Threadsafe => "threadsafe",
            Feature::UnixSockets => "UnixSockets",
            Feature::Zstd => "zstd",
        }
    }
}

/// Sorted by name, case-insensitively, as C lists them.
const FEATURES: &[Feature] = &[
    Feature::AltSvc,
    #[cfg(feature = "apple-sectrust")]
    Feature::AppleSecTrust,
    Feature::AsynchDns,
    Feature::Brotli,
    #[cfg(feature = "debug-hooks")]
    Feature::Debug,
    Feature::GssApi,
    Feature::Hsts,
    Feature::Http2,
    Feature::Http3,
    Feature::HttpsProxy,
    Feature::Httpsig,
    Feature::HttpsRr,
    Feature::Idn,
    Feature::Ipv6,
    Feature::Kerberos,
    Feature::Largefile,
    Feature::Libz,
    Feature::ProxyHttp3,
    Feature::Psl,
    Feature::Spnego,
    Feature::Ssl,
    Feature::SslsExport,
    Feature::Threadsafe,
    Feature::UnixSockets,
    Feature::Zstd,
];

pub use crate::url::schemes::Protocol;

impl Protocol {
    /// The protocol of `scheme`, in lowercase, if this build has it: one
    /// of `version().protocols`.
    pub fn of_scheme(scheme: &[u8]) -> Option<Protocol> {
        let known = crate::url::schemes::KNOWN
            .iter()
            .find(|k| k.name.as_bytes() == scheme)?;
        known.protocol.filter(|p| VERSION.protocols.contains(p))
    }
}

/// Version and build information.
#[derive(Debug)]
pub struct VersionInfo {
    /// The version string, such as `8.23.1-DEV`.
    pub version: &'static str,
    pub release: Release,
    /// When it was released, or `[unreleased]`.
    pub timestamp: &'static str,
    /// The operating system the library was built for.
    pub host: &'static str,
    /// Sorted by name, case-insensitively.
    pub features: &'static [Feature],
    /// Sorted by name.
    pub protocols: &'static [Protocol],
}

impl VersionInfo {
    /// Whether the build claims the feature `curl -V` lists as `name`,
    /// as C's tool asks of `curl_version_info` (`feature_spnego`): a
    /// capability the build lacks has no `Feature` to ask with.
    pub fn claims(&self, name: &str) -> bool {
        self.features
            .iter()
            .any(|f| f.name().eq_ignore_ascii_case(name))
    }

    /// The library and the libraries it is linked with, as `curl_version`
    /// lists them: `libcurl/8.23.1-DEV zlib/1.3.1`. The core links none of
    /// them itself: what links it names them, in C's order (TLS, zlib,
    /// brotli, zstd, c-ares, IDN, libpsl, ...).
    pub fn components<'a>(&'a self, libraries: &'a [&'a dyn fmt::Display]) -> Components<'a> {
        Components(self, libraries)
    }
}

/// A library linked in, as the version string names it: `zlib/1.3.1`.
pub struct Library<V>(pub &'static str, pub V);

impl<V: fmt::Display> fmt::Display for Library<V> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.0, self.1)
    }
}

/// See [`VersionInfo::components`].
pub struct Components<'a>(&'a VersionInfo, &'a [&'a dyn fmt::Display]);

impl fmt::Display for Components<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // The debug test build says what `CURL_DEBUG_VERSION` says, as
        // much of it as C's buffer of 300 holds.
        #[cfg(feature = "debug-hooks")]
        if let Some(given) = curl_os::env::var_into(b"CURL_DEBUG_VERSION", &mut [0u8; 299]) {
            return curl_alloc::Lossy(given).fmt(f);
        }
        write!(f, "libcurl/{}", self.0.version)?;
        for library in self.1 {
            write!(f, " {library}")?;
        }
        Ok(())
    }
}

static VERSION: VersionInfo = VersionInfo {
    version: curlver::VERSION,
    release: Release {
        major: curlver::MAJOR,
        minor: curlver::MINOR,
        patch: curlver::PATCH,
    },
    timestamp: curlver::TIMESTAMP,
    host: HOST,
    features: FEATURES,
    protocols: PROTOCOLS,
};

/// The protocols built, in C's order. LDAP's two only where the LDAP
/// crate links an LDAP library (`curl_build::ldap`): Windows' build has
/// WinLDAP, not bound yet, so it has neither LDAP protocol, as a C build
/// without LDAP has not.
#[cfg(ldap)]
const PROTOCOLS: &[Protocol] = &[
    Protocol::Dict,
    Protocol::File,
    Protocol::Ftp,
    Protocol::Ftps,
    Protocol::Gopher,
    Protocol::Gophers,
    Protocol::Http,
    Protocol::Https,
    Protocol::Imap,
    Protocol::Imaps,
    Protocol::Ldap,
    Protocol::Ldaps,
    Protocol::Mqtt,
    Protocol::Mqtts,
    Protocol::Pop3,
    Protocol::Pop3s,
    Protocol::Rtsp,
    Protocol::Scp,
    Protocol::Sftp,
    Protocol::Smtp,
    Protocol::Smtps,
    Protocol::Telnet,
    Protocol::Tftp,
    Protocol::Ws,
    Protocol::Wss,
];

#[cfg(not(ldap))]
const PROTOCOLS: &[Protocol] = &[
    Protocol::Dict,
    Protocol::File,
    Protocol::Ftp,
    Protocol::Ftps,
    Protocol::Gopher,
    Protocol::Gophers,
    Protocol::Http,
    Protocol::Https,
    Protocol::Imap,
    Protocol::Imaps,
    Protocol::Mqtt,
    Protocol::Mqtts,
    Protocol::Pop3,
    Protocol::Pop3s,
    Protocol::Rtsp,
    Protocol::Scp,
    Protocol::Sftp,
    Protocol::Smtp,
    Protocol::Smtps,
    Protocol::Telnet,
    Protocol::Tftp,
    Protocol::Ws,
    Protocol::Wss,
];

#[cfg(target_os = "linux")]
const HOST: &str = "Linux";
/// What C's CMake build names macOS, as `curl -V` shows it there.
#[cfg(target_os = "macos")]
const HOST: &str = "Darwin";
/// What C's CMake build names Windows (`CMAKE_SYSTEM_NAME`).
#[cfg(windows)]
const HOST: &str = "Windows";

/// This build's version information.
pub fn version() -> &'static VersionInfo {
    &VERSION
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The protocols are listed by their schemes, in order, as C lists
    /// them, and each scheme names its protocol.
    #[test]
    fn protocols_are_named_by_their_schemes() {
        let names: Vec<_> = version().protocols.iter().map(|p| p.name()).collect();
        let mut want = vec![
            "dict", "file", "ftp", "ftps", "gopher", "gophers", "http", "https", "imap", "imaps",
            "ldap", "ldaps", "mqtt", "mqtts", "pop3", "pop3s", "rtsp", "scp", "sftp", "smtp",
            "smtps", "telnet", "tftp", "ws", "wss",
        ];
        // No LDAP without an LDAP library.
        if !cfg!(ldap) {
            want.retain(|p| !p.starts_with("ldap"));
        }
        assert_eq!(names, want);
        for &p in version().protocols {
            assert_eq!(Protocol::of_scheme(p.name().as_bytes()), Some(p));
        }
    }

    /// Each feature is listed under the name `curl -V` gives it.
    #[test]
    fn features_are_named_as_c_names_them() {
        let names: Vec<_> = version().features.iter().map(|f| f.name()).collect();
        assert!(names.contains(&"IPv6"), "{names:?}");
        assert!(names.contains(&"UnixSockets"), "{names:?}");
    }

    /// Listed in C's order, by name whatever the case.
    #[test]
    fn features_are_sorted_as_c_sorts_them() {
        let names: Vec<_> = version().features.iter().map(|f| f.name()).collect();
        let mut sorted = names.clone();
        sorted.sort_by_key(|n| n.to_ascii_lowercase());
        assert_eq!(names, sorted);
    }

    /// The threaded resolver is claimed as C claims its own, as
    /// `AsynchDNS`, which tells runtests the resolver is threaded; the
    /// resolver that answers as it starts blocks, and is not. Both are
    /// `threadsafe`, as nothing they keep is process-wide.
    #[test]
    fn the_threaded_resolver_is_claimed_as_asynch_dns() {
        let v = version();
        assert!(v.claims("AsynchDNS"));
        assert!(v.claims("threadsafe"));
    }

    /// `Debug`, which tells runtests the build has the debug hooks, is
    /// claimed by a build with them and by no other.
    #[test]
    fn the_debug_hooks_are_claimed_as_debug() {
        assert_eq!(version().claims("Debug"), cfg!(feature = "debug-hooks"));
    }

    /// A feature is claimed by its name in any case, as C's tool matches
    /// it; one the build lacks is not.
    #[test]
    fn claims_a_listed_feature_by_name() {
        let v = version();
        assert!(v.claims("IPv6"));
        assert!(v.claims("ipv6"));
        assert!(!v.claims("NTLM"));
        assert!(!v.claims("IPv"));
    }

    #[test]
    fn version_matches_its_parts() {
        let v = version();
        let r = v.release;
        assert!(
            v.version
                .starts_with(&format!("{}.{}.{}", r.major, r.minor, r.patch)),
            "{v:?}"
        );
        assert_eq!(
            v.components(&[]).to_string(),
            format!("libcurl/{}", v.version)
        );
        let zlib = Library("zlib", "1.3.1");
        let psl = Library("libpsl", "0.21.5");
        assert_eq!(
            v.components(&[&zlib, &psl]).to_string(),
            format!("libcurl/{} zlib/1.3.1 libpsl/0.21.5", v.version)
        );
    }
}
