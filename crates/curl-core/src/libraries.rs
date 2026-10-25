//! What the C libraries bound beside the core do for a handle: the
//! content codings they undo, the signatures they make, the TLS they
//! speak and the GSS-API they authenticate with. The core links none of
//! them; whoever builds a handle (the shim, the tool) gives it a
//! `SharedLibraries` naming what its build has: a static the process
//! keeps for good, or a `Libraries` its owner shares with its handles.

use std::fmt;
use std::ops::Deref;

use curl_alloc::{OutOfMemory, TryArc};

use crate::coding::Decoders;
use crate::gss::Gss;
use crate::tls::TlsBackend;

/// The libraries a handle uses. A handle without any is given
/// `Libraries::NONE`: it undoes no coding, signs no Ed25519, speaks no
/// TLS and knows no GSS-API.
#[derive(Debug)]
pub struct Libraries {
    /// The content codings it undoes.
    pub decoders: Decoders,
    /// What signs HTTP message signatures under Ed25519, if anything
    /// does: without it, they are refused as in a C build whose TLS
    /// library lacks it.
    pub ed25519: Option<&'static dyn Ed25519>,
    /// The TLS library, if any: without it, no scheme that needs TLS is
    /// built in, as in a C build without one. It may keep state (the key
    /// log), so a `Libraries` of its own may own it.
    pub tls: Option<Library<dyn TlsBackend>>,
    /// The GSS-API library, if any: without it, Negotiate and SOCKS5's
    /// GSS-API method are not built in, as in a C build without one.
    pub gss: Option<&'static dyn Gss>,
}

impl Libraries {
    pub const NONE: Libraries = Libraries {
        decoders: Decoders::none(),
        ed25519: None,
        tls: None,
        gss: None,
    };
}

/// A library `Libraries` names: one the process keeps for good, or one
/// the `Libraries` owns.
pub enum Library<T: ?Sized + 'static> {
    Static(&'static T),
    Owned(Box<T>),
}

impl<T: ?Sized + 'static> Deref for Library<T> {
    type Target = T;

    fn deref(&self) -> &T {
        match self {
            Library::Static(library) => library,
            Library::Owned(library) => library,
        }
    }
}

impl<T: ?Sized + fmt::Debug + 'static> fmt::Debug for Library<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        (**self).fmt(f)
    }
}

/// The libraries a handle is given, as `Components` are given: the
/// static ones a process keeps for good (the shim's), or ones their owner
/// shares, which last as long as the last handle given them (the tool's).
#[derive(Clone, Debug)]
pub struct SharedLibraries(Backing);

#[derive(Clone, Debug)]
enum Backing {
    Shared(TryArc<Libraries>),
    Static(&'static Libraries),
}

impl SharedLibraries {
    /// `libraries`, shared from now on.
    pub fn new(libraries: Libraries) -> Result<SharedLibraries, OutOfMemory> {
        Ok(SharedLibraries(Backing::Shared(TryArc::try_new(
            libraries,
        )?)))
    }

    /// Libraries a process keeps for good.
    pub const fn of_static(libraries: &'static Libraries) -> SharedLibraries {
        SharedLibraries(Backing::Static(libraries))
    }
}

impl Default for SharedLibraries {
    fn default() -> SharedLibraries {
        SharedLibraries::of_static(&Libraries::NONE)
    }
}

impl Deref for SharedLibraries {
    type Target = Libraries;

    fn deref(&self) -> &Libraries {
        match &self.0 {
            Backing::Shared(shared) => shared,
            Backing::Static(libraries) => libraries,
        }
    }
}

/// An Ed25519 key's private part, as RFC 8032 names it: 32 bytes.
pub const ED25519_KEY_LEN: usize = 32;

/// An Ed25519 signature: 64 bytes.
pub const ED25519_SIGNATURE_LEN: usize = 64;

/// Signs under Ed25519 (RFC 8032), as C's `Curl_ed25519_sign`.
pub trait Ed25519: Send + Sync {
    /// `message` signed with the private key `key`.
    fn sign(
        &self,
        key: &[u8; ED25519_KEY_LEN],
        message: &[u8],
    ) -> Result<[u8; ED25519_SIGNATURE_LEN], Ed25519Error>;
}

impl fmt::Debug for dyn Ed25519 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Ed25519")
    }
}

/// Why a signature was not made.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Ed25519Error {
    /// The library cannot sign in this process: it is not the version
    /// the build needs.
    Unavailable,
    OutOfMemory,
    /// The library refused the key or the signing.
    Failed,
}

#[cfg(test)]
pub(crate) mod testing {
    use super::*;

    /// Signs as no Ed25519 does, but so that the signature shows what it
    /// was asked: the key, then the message's HMAC-SHA256 under it.
    pub(crate) struct Keyed;

    impl Ed25519 for Keyed {
        fn sign(
            &self,
            key: &[u8; ED25519_KEY_LEN],
            message: &[u8],
        ) -> Result<[u8; ED25519_SIGNATURE_LEN], Ed25519Error> {
            let mut signature = [0; ED25519_SIGNATURE_LEN];
            signature[..32].copy_from_slice(key);
            signature[32..].copy_from_slice(&crate::hash::hmac_sha256(key, &[message]));
            Ok(signature)
        }
    }

    /// Fails each signing as it says.
    pub(crate) struct Failing(pub(crate) Ed25519Error);

    impl Ed25519 for Failing {
        fn sign(
            &self,
            _: &[u8; ED25519_KEY_LEN],
            _: &[u8],
        ) -> Result<[u8; ED25519_SIGNATURE_LEN], Ed25519Error> {
            Err(self.0)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A handle's libraries print the signer by what it does, whichever
    /// library it is.
    #[test]
    fn libraries_print_their_signer() {
        static KEYED: testing::Keyed = testing::Keyed;
        let libraries = Libraries {
            ed25519: Some(&KEYED),
            ..Libraries::NONE
        };
        let printed = format!("{libraries:?}");
        assert!(
            printed.ends_with("ed25519: Some(Ed25519), tls: None, gss: None }"),
            "{printed}"
        );
    }
}
