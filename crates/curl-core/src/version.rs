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
    /// The `br` content coding is undone by brotli, which the tool and the
    /// C ABI give every handle.
    Brotli,
    /// A debug build, for the test suite: never for production.
    #[cfg(feature = "debug-hooks")]
    Debug,
    /// HTTP message signatures (RFC 9421), though only with HMAC-SHA256.
    Httpsig,
    /// Connections over IPv6, and its addresses in URLs.
    Ipv6,
    /// The `deflate` and `gzip` content codings are undone by zlib, which
    /// the tool and the C ABI give every handle.
    Libz,
    /// Cookies' domains are checked against libpsl's public suffixes,
    /// which the tool and the C ABI give every handle.
    Psl,
    /// TLS, by OpenSSL, which the tool and the C ABI give every handle.
    Ssl,
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
            Feature::Brotli => "brotli",
            #[cfg(feature = "debug-hooks")]
            Feature::Debug => "Debug",
            Feature::Httpsig => "HTTPSIG",
            Feature::Ipv6 => "IPv6",
            Feature::Libz => "libz",
            Feature::Psl => "PSL",
            Feature::Ssl => "SSL",
            Feature::UnixSockets => "UnixSockets",
            Feature::Zstd => "zstd",
        }
    }
}

#[cfg(feature = "debug-hooks")]
const FEATURES: &[Feature] = &[
    Feature::Brotli,
    Feature::Debug,
    Feature::Httpsig,
    Feature::Ipv6,
    Feature::Libz,
    Feature::Psl,
    Feature::Ssl,
    Feature::UnixSockets,
    Feature::Zstd,
];
#[cfg(not(feature = "debug-hooks"))]
const FEATURES: &[Feature] = &[
    Feature::Brotli,
    Feature::Httpsig,
    Feature::Ipv6,
    Feature::Libz,
    Feature::Psl,
    Feature::Ssl,
    Feature::UnixSockets,
    Feature::Zstd,
];

/// A URL scheme the build can transfer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Protocol {
    File,
    Http,
    /// HTTP over TLS, which the tool and the C ABI give every handle.
    Https,
}

impl Protocol {
    /// The protocol of `scheme`, in lowercase, if the build has it.
    pub fn of_scheme(scheme: &[u8]) -> Option<Protocol> {
        match scheme {
            b"file" => Some(Protocol::File),
            b"http" => Some(Protocol::Http),
            b"https" => Some(Protocol::Https),
            _ => None,
        }
    }

    /// The scheme, in lowercase.
    pub fn name(self) -> &'static str {
        match self {
            Protocol::File => "file",
            Protocol::Http => "http",
            Protocol::Https => "https",
        }
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
            return f.write_str(&String::from_utf8_lossy(given));
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
    protocols: &[Protocol::File, Protocol::Http, Protocol::Https],
};

#[cfg(target_os = "linux")]
const HOST: &str = "Linux";

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
        assert_eq!(names, ["file", "http", "https"]);
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
