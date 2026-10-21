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
    /// A debug build, for the test suite: never for production.
    #[cfg(feature = "debug-hooks")]
    Debug,
}

impl Feature {
    /// The name `curl -V` lists it under.
    pub fn name(self) -> &'static str {
        match self {
            #[cfg(feature = "debug-hooks")]
            Feature::Debug => "Debug",
        }
    }
}

#[cfg(feature = "debug-hooks")]
const FEATURES: &[Feature] = &[Feature::Debug];
#[cfg(not(feature = "debug-hooks"))]
const FEATURES: &[Feature] = &[];

/// A URL scheme the build can transfer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Protocol {
    File,
    Http,
}

impl Protocol {
    /// The protocol of `scheme`, in lowercase, if the build has it.
    pub fn of_scheme(scheme: &[u8]) -> Option<Protocol> {
        match scheme {
            b"file" => Some(Protocol::File),
            b"http" => Some(Protocol::Http),
            _ => None,
        }
    }

    /// The scheme, in lowercase.
    pub fn name(self) -> &'static str {
        match self {
            Protocol::File => "file",
            Protocol::Http => "http",
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
    /// The library and the components it was built with, as in
    /// `libcurl/8.23.1-DEV`.
    pub fn components(&self) -> Components<'_> {
        Components(self)
    }
}

/// See [`VersionInfo::components`].
pub struct Components<'a>(&'a VersionInfo);

impl fmt::Display for Components<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "libcurl/{}", self.0.version)
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
    protocols: &[Protocol::File, Protocol::Http],
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
        assert_eq!(names, ["file", "http"]);
        for &p in version().protocols {
            assert_eq!(Protocol::of_scheme(p.name().as_bytes()), Some(p));
        }
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
        assert_eq!(v.components().to_string(), format!("libcurl/{}", v.version));
    }
}
