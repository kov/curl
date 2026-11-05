//! Schannel for the curl rewrite: TLS through Windows' own security
//! package, as `lib/vtls/schannel.c` drives it, with the peer's checks
//! of `lib/vtls/schannel_verify.c`, behind `curl_core::tls::TlsBackend`.
//! On any other system the crate is empty.

#![cfg_attr(test, allow(clippy::disallowed_methods, clippy::disallowed_macros))]

#[cfg(windows)]
mod algs;
#[cfg(windows)]
mod client;
#[cfg(windows)]
mod crypt;
#[cfg(windows)]
mod session;
#[cfg(windows)]
mod sspi;
#[cfg(windows)]
mod text;
#[cfg(windows)]
mod verify;

#[cfg(windows)]
pub use backend::{SCHANNEL, Schannel};

#[cfg(windows)]
mod backend {
    use curl_alloc::{OutOfMemory, TryArc, try_box};
    use curl_core::error::ErrorKind;
    use curl_core::tls::{
        Alpn, CaDefaults, TlsBackend, TlsIdentity, TlsPeer, TlsSession, TlsShared,
    };

    use crate::session::Session;

    /// Schannel, as the core's TLS library.
    #[derive(Debug)]
    pub struct Schannel;

    /// Schannel.
    pub static SCHANNEL: Schannel = Schannel;

    impl TlsBackend for Schannel {
        /// Its name, as C's `schannel_version` says it.
        fn id(&self) -> &dyn core::fmt::Display {
            &"Schannel"
        }

        fn session(
            &self,
            identity: &TryArc<TlsIdentity>,
            peer: &TlsPeer<'_>,
            alpn: Alpn,
            shared: &TlsShared,
        ) -> Result<Box<dyn TlsSession>, ErrorKind> {
            let session = Session::new(identity, peer, alpn, shared)?;
            Ok(try_box(session).map_err(|OutOfMemory| ErrorKind::OutOfMemory)?)
        }

        /// None: the system's store is Schannel's, and a build of it
        /// names no bundle.
        fn ca_defaults(&self) -> CaDefaults {
            CaDefaults::default()
        }
    }
}
