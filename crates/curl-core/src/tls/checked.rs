//! What a session proves of its peer as its handshake ends (`Checked`):
//! the checks curl-core makes itself, bound to the session's identity,
//! and the weaknesses its backend reports it kept (`Residuals`). The
//! checks a library makes (the chain, the status, the issuer, the name
//! where the library matches it) are not proved here: their tests and
//! sabotage entries guard them.

use std::fmt;

use curl_alloc::TryArc;

use super::hostcheck::NameMatch;
use super::pin::Pinned;
use super::{SessionPeer, TlsCx, TlsIdentity};
use crate::error::ErrorKind;

/// A weakness a session's check of its peer keeps, named by what it does.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Residual {
    /// The peer's name is checked only with its chain: with the host to
    /// be checked and the peer not to be verified, neither is.
    HostCheckFollowsChain,
    /// The application set the library's context up itself
    /// (`CURLOPT_SSL_CTX_FUNCTION`), and may have changed what the
    /// library verifies: what it says of the chain is the application's.
    AppHadContext,
    /// Made by a test, of no check.
    Testing,
}

impl Residual {
    fn bit(self) -> u8 {
        match self {
            Residual::HostCheckFollowsChain => 1,
            Residual::AppHadContext => 2,
            Residual::Testing => 4,
        }
    }
}

/// The residuals of one check.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Residuals(u8);

impl Residuals {
    pub const NONE: Residuals = Residuals(0);

    /// The backend checks the peer's name only with its chain: kept where
    /// the session's identity asks for the name to be checked and not
    /// the peer, which is where it weakens the check; nothing otherwise.
    #[must_use]
    pub fn host_check_follows_chain(self, io: &TlsCx<'_>) -> Residuals {
        let identity = io.identity();
        if identity.verify_host && !identity.verify_peer {
            self.with(Residual::HostCheckFollowsChain)
        } else {
            self
        }
    }

    /// It holds `residual`.
    pub fn has(self, residual: Residual) -> bool {
        self.0 & residual.bit() != 0
    }

    fn with(self, residual: Residual) -> Residuals {
        Residuals(self.0 | residual.bit())
    }
}

/// The session's peer was checked, as far as curl-core proves it: the
/// pinned key compared where the identity pins one, and, where the
/// backend's name check is curl-core's, the name matched where the
/// identity asks for it; each for this session's identity. Made only by
/// [`Checked::new`] and [`Checked::named`], from data curl-core reads
/// itself. A connection's TLS layer, and its QUIC connection, take a
/// session as open only with one for their own identity.
///
/// Neither it nor the tokens it is made of can be made outside their
/// modules, as a backend crate sees them:
///
/// ```compile_fail
/// let c = curl_core::tls::Checked {
///     identity: unimplemented!(),
///     pinned: true,
///     named_in_core: true,
///     residuals: curl_core::tls::Residuals::NONE,
/// };
/// ```
/// ```compile_fail
/// let p = curl_core::tls::pin::Pinned { identity: unimplemented!(), matched: true };
/// ```
/// ```compile_fail
/// let a = curl_core::tls::pin::PinAsk { identity: unimplemented!() };
/// ```
/// ```compile_fail
/// let n = curl_core::tls::hostcheck::NameMatch { identity: unimplemented!() };
/// ```
#[derive(Clone)]
pub struct Checked {
    identity: TryArc<TlsIdentity>,
    pinned: bool,
    /// The name was matched by curl-core (or not asked for), not by the
    /// library.
    named_in_core: bool,
    residuals: Residuals,
}

impl Checked {
    /// The check of a session whose library matches the peer's name, its
    /// pin `pin`, keeping `residuals`. Fails closed if `pin` is not this
    /// session's.
    pub fn new(
        io: &mut TlsCx<'_>,
        pin: Pinned,
        residuals: Residuals,
    ) -> Result<Checked, ErrorKind> {
        Checked::made(io, pin, None, false, residuals)
    }

    /// The check of a session whose peer's name curl-core matches
    /// (`hostcheck::check`): `name`, which the identity asking for the
    /// name to be checked must have. Fails closed without it, or if a
    /// token is not this session's.
    pub fn named(
        io: &mut TlsCx<'_>,
        pin: Pinned,
        name: Option<NameMatch>,
        residuals: Residuals,
    ) -> Result<Checked, ErrorKind> {
        Checked::made(io, pin, name, true, residuals)
    }

    fn made(
        io: &mut TlsCx<'_>,
        pin: Pinned,
        name: Option<NameMatch>,
        in_core: bool,
        residuals: Residuals,
    ) -> Result<Checked, ErrorKind> {
        let identity = io.identity().clone();
        let why = if !pin.is_for(&identity) {
            Some("a pin checked for another session")
        } else if name.as_ref().is_some_and(|n| !n.is_for(&identity)) {
            Some("a name matched for another session")
        } else if in_core && identity.verify_host && name.is_none() {
            Some("the peer's name was not checked")
        } else {
            None
        };
        if let Some(why) = why {
            return Err(io.fail(
                ErrorKind::PeerFailedVerification,
                format_args!("internal: {why}"),
            ));
        }
        let residuals = if io.configures_context() {
            residuals.with(Residual::AppHadContext)
        } else {
            residuals
        };
        Ok(Checked {
            pinned: pin.matched(),
            identity,
            named_in_core: in_core,
            residuals,
        })
    }

    /// The weaknesses the check kept.
    pub fn residuals(&self) -> Residuals {
        self.residuals
    }

    /// The pinned key was compared and matched; else none was pinned.
    pub fn pinned(&self) -> bool {
        self.pinned
    }

    /// It was made for the connection whose sessions `peer` names: the
    /// same identity, not one equal to it.
    pub(crate) fn is_for(&self, peer: &SessionPeer) -> bool {
        TryArc::ptr_eq(&self.identity, peer.identity())
    }

    /// It was made for the session `io` works for, as `is_for`.
    pub(crate) fn is_for_session(&self, io: &TlsCx<'_>) -> bool {
        TryArc::ptr_eq(&self.identity, io.identity())
    }

    /// One for the session `io` works for, of no check, its residuals
    /// saying so: for the tests of what takes one.
    #[cfg(any(test, feature = "test-util"))]
    pub fn testing(io: &TlsCx<'_>) -> Checked {
        Checked {
            identity: io.identity().clone(),
            pinned: false,
            named_in_core: false,
            residuals: Residuals::NONE.with(Residual::Testing),
        }
    }

    /// One of no check for the session of `peer`, which need not be the
    /// session it is given to: for the tests of a check made for another.
    #[cfg(test)]
    pub(crate) fn testing_for(peer: &SessionPeer) -> Checked {
        Checked {
            identity: peer.identity().clone(),
            pinned: false,
            named_in_core: false,
            residuals: Residuals::NONE.with(Residual::Testing),
        }
    }
}

/// Two checks are the same if made for the same identity and saying the
/// same.
impl PartialEq for Checked {
    fn eq(&self, other: &Checked) -> bool {
        TryArc::ptr_eq(&self.identity, &other.identity)
            && self.pinned == other.pinned
            && self.named_in_core == other.named_in_core
            && self.residuals == other.residuals
    }
}

impl Eq for Checked {}

impl fmt::Debug for Checked {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Checked")
            .field("pinned", &self.pinned)
            .field("named_in_core", &self.named_in_core)
            .field("residuals", &self.residuals)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests;
