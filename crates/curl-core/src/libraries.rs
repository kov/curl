//! What the C libraries bound beside the core do for a handle: the
//! content codings they undo, the signatures they make, the TLS and SSH
//! they speak and the GSS-API they authenticate with. The core links none of
//! them; whoever builds a handle (the shim, the tool) gives it a
//! `SharedLibraries` naming what its build has: a static the process
//! keeps for good, or a `Libraries` its owner shares with its handles.

use std::fmt;
use std::ops::Deref;

use curl_alloc::{OutOfMemory, TryArc};

use crate::coding::Decoders;
use crate::gss::Gss;
use crate::http2::Http2;
use crate::http3::Http3;
use crate::idn::Idn;
use crate::ldap::Ldap;
use crate::psl::SuffixLibrary;
use crate::ssh::Ssh;
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
    /// What resolves names with a resolve of its own for each, if anything:
    /// without it, the network's resolver does.
    pub dns: Option<&'static dyn crate::conn::io::DnsLibrary>,
    /// What converts host names not in ASCII, if anything: without it,
    /// they are sent as they are, as in a C build without one.
    pub idn: Option<&'static dyn Idn>,
    /// The HTTP/2 library, if any: without it, HTTP/2 is not built in, as
    /// in a C build without nghttp2.
    pub h2: Option<&'static dyn Http2>,
    /// The HTTP/3 library, if any: without it, HTTP/3 is not built in, as
    /// in a C build without ngtcp2.
    pub h3: Option<&'static dyn Http3>,
    /// The SSH library, if any: without it, SCP and SFTP are not built
    /// in, as in a C build without libssh.
    pub ssh: Option<&'static dyn Ssh>,
    /// The LDAP library, if any: without it, LDAP is not built in, as in
    /// a C build without OpenLDAP.
    pub ldap: Option<&'static dyn Ldap>,
    /// Where public suffix lists come from, if anywhere: without it, a
    /// cookie's domain needs a dot, as in a C build without libpsl.
    pub psl: Option<&'static dyn SuffixLibrary>,
    /// Where random bytes come from in place of the system, if anywhere:
    /// the debug build's `CURL_ENTROPY` numbers.
    pub random: Option<Library<dyn Random>>,
}

/// A source of random bytes, standing in for the system's.
pub trait Random: Send + Sync {
    /// Whether it stands in now: if not, the system's are drawn.
    fn active(&self) -> bool {
        true
    }

    /// Fill `bytes`.
    fn fill(&self, bytes: &mut [u8]) -> std::io::Result<()>;
}

impl fmt::Debug for dyn Random {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Random")
    }
}

/// The numbers C's debug build draws its random bytes from when
/// `CURL_ENTROPY` is set (`randit`): the variable's first four bytes,
/// big-endian, then one more at each draw of four bytes, each laid out
/// in the machine's order. Clones draw from the one sequence, as C's is
/// the process's.
#[cfg(feature = "debug-hooks")]
#[derive(Clone, Debug)]
pub struct ForcedEntropy {
    next: TryArc<std::sync::Mutex<u32>>,
}

#[cfg(feature = "debug-hooks")]
impl ForcedEntropy {
    /// The sequence `given`, the variable's value, seeds.
    pub fn seeded(given: &[u8]) -> Result<ForcedEntropy, OutOfMemory> {
        let mut seed = [0u8; 4];
        let n = given.len().min(4);
        seed[..n].copy_from_slice(&given[..n]);
        Ok(ForcedEntropy {
            next: TryArc::try_new(std::sync::Mutex::new(u32::from_be_bytes(seed)))?,
        })
    }
}

#[cfg(feature = "debug-hooks")]
impl Random for ForcedEntropy {
    fn fill(&self, bytes: &mut [u8]) -> std::io::Result<()> {
        let mut next = self.next.lock().expect("no draw panics");
        for chunk in bytes.chunks_mut(4) {
            chunk.copy_from_slice(&next.to_ne_bytes()[..chunk.len()]);
            *next = next.wrapping_add(1);
        }
        Ok(())
    }
}

impl Libraries {
    pub const NONE: Libraries = Libraries {
        dns: None,
        decoders: Decoders::none(),
        ed25519: None,
        tls: None,
        gss: None,
        idn: None,
        h2: None,
        h3: None,
        ssh: None,
        ldap: None,
        psl: None,
        random: None,
    };

    /// Random bytes into `bytes`: the stand-in's, or the system's.
    pub(crate) fn random(&self, bytes: &mut [u8]) -> std::io::Result<()> {
        match &self.random {
            Some(r) if r.active() => r.fill(bytes),
            _ => curl_os::random::fill(bytes),
        }
    }
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

    /// `CURL_ENTROPY`'s numbers: its first four bytes big-endian, one
    /// more each four bytes drawn, each in the machine's order; a stand-in
    /// that is not active leaves the system's bytes, and one that is
    /// prints as what it is.
    #[cfg(feature = "debug-hooks")]
    #[test]
    fn random_bytes_come_from_the_active_stand_in() {
        struct Off;
        impl Random for Off {
            fn active(&self) -> bool {
                false
            }
            fn fill(&self, bytes: &mut [u8]) -> std::io::Result<()> {
                bytes.fill(0xaa);
                Ok(())
            }
        }
        let forced = ForcedEntropy::seeded(b"12345678").unwrap();
        assert!(forced.active());
        let libraries = Libraries {
            random: Some(Library::Owned(Box::new(forced))),
            ..Libraries::NONE
        };
        let mut drawn = [0u8; 10];
        libraries.random(&mut drawn).unwrap();
        let mut want = Vec::new();
        for n in 0x3132_3334u32..0x3132_3337 {
            want.extend_from_slice(&n.to_ne_bytes());
        }
        assert_eq!(drawn, want[..10]);
        let mut next = [0u8; 4];
        libraries.random(&mut next).unwrap();
        assert_eq!(next, 0x3132_3337u32.to_ne_bytes());
        assert!(format!("{libraries:?}").ends_with("random: Some(Random) }"));
        let off = Libraries {
            random: Some(Library::Owned(Box::new(Off))),
            ..Libraries::NONE
        };
        let mut a = [0xaau8; 32];
        off.random(&mut a).unwrap();
        assert_ne!(a, [0xaa; 32], "the system's bytes");
    }

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
            printed.ends_with(
                "ed25519: Some(Ed25519), tls: None, gss: None, dns: None, idn: None, h2: None, h3: None, ssh: None, ldap: None, psl: None, random: None }"
            ),
            "{printed}"
        );
    }
}
