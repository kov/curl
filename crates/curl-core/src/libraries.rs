//! What the C libraries bound beside the core do for a handle: the
//! content codings they undo, the signatures they make and the TLS they
//! speak. The core links none of them; whoever builds a handle (the shim,
//! the tool) gives it one `&'static Libraries` naming what its build has.

use std::fmt;

use crate::coding::Decoders;
use crate::tls::TlsBackend;

/// The libraries a handle uses. A handle without any is given
/// `Libraries::NONE`: it undoes no coding, signs no Ed25519 and speaks no
/// TLS.
#[derive(Clone, Copy, Debug)]
pub struct Libraries {
    /// The content codings it undoes.
    pub decoders: Decoders,
    /// What signs HTTP message signatures under Ed25519, if anything
    /// does: without it, they are refused as in a C build whose TLS
    /// library lacks it.
    pub ed25519: Option<&'static dyn Ed25519>,
    /// The TLS library, if any: without it, no scheme that needs TLS is
    /// built in, as in a C build without one.
    pub tls: Option<&'static dyn TlsBackend>,
}

impl Libraries {
    pub const NONE: Libraries = Libraries {
        decoders: Decoders::none(),
        ed25519: None,
        tls: None,
    };
}

impl Default for &'static Libraries {
    fn default() -> &'static Libraries {
        &Libraries::NONE
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
            printed.ends_with("ed25519: Some(Ed25519), tls: None }"),
            "{printed}"
        );
    }
}
