//! Whether what the application said may go to the party a request is
//! for (`Curl_auth_allowed_to_host`, `Curl_peer_equal` of the first
//! origin and the request's): the transfer's first origin is kept here,
//! and a request's gate is decided here alone, for the peer the request
//! is made for (`RequestBase::new`, which alone holds the key).
//!
//! What a gate lets through is a token taken from it: `SameOrigin` for
//! what goes to the first origin alone, `OriginTrusted` for what the
//! application said. Credentials the request's own URL or a `.netrc` entry
//! carry go to their origin by `OwnLeave`, which opens nothing else.

use crate::conn::Peer;
use crate::multi::state::Origin;
use crate::proto::GateKey;

/// Where the transfer's first request went (`state.initial_origin`): what
/// the application said for it goes nowhere else. A run records it as its
/// first request over a network is addressed, before that request's gate
/// is decided ([`FirstOrigin::lend`]), so every gate compares with one.
#[derive(Debug)]
pub(crate) struct FirstOrigin(Option<Origin>);

impl FirstOrigin {
    /// A run's before its first request.
    pub(crate) fn fresh() -> FirstOrigin {
        FirstOrigin(None)
    }

    /// A pushed stream's run, which makes no first request of its own:
    /// the first origin of the request it was promised on (C links the
    /// pushed handle's `initial_origin` to its parent's).
    pub(crate) fn inherited(first: Origin) -> FirstOrigin {
        FirstOrigin(Some(first))
    }

    /// The transfer starts over.
    pub(crate) fn reset(&mut self) {
        self.0 = None;
    }

    /// What a request of this run to `peer` decides its gate by: the
    /// first origin, `peer` itself if it is the run's first request over a
    /// network, which is recorded here and nowhere else
    /// (`url_set_data_origin_and_creds`); `unrestricted` lets credentials
    /// follow it anywhere (`CURLOPT_UNRESTRICTED_AUTH`).
    pub(crate) fn lend(
        &mut self,
        peer: &Peer,
        unrestricted: bool,
    ) -> Result<Origins<'_>, curl_alloc::OutOfMemory> {
        let first = match self.0.take() {
            Some(first) => first,
            None => curl_alloc::TryArc::try_new(peer.try_clone()?)?,
        };
        Ok(Origins {
            first: self.0.insert(first),
            unrestricted,
        })
    }
}

/// The first origin as a request is lent it (`Before`): it answers only
/// to the holder of the key, `RequestBase`, for the peer it stores.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Origins<'r> {
    first: &'r Origin,
    unrestricted: bool,
}

impl<'r> Origins<'r> {
    /// The gate of a request to `peer`: whether `peer` is the first
    /// origin, and whether what the application said may go there
    /// (`Curl_auth_allowed_to_host`).
    pub(crate) fn gate(&self, peer: &Peer, _: GateKey) -> CredentialGate {
        let same = **self.first == *peer;
        CredentialGate {
            same,
            trusted: same || self.unrestricted,
        }
    }

    /// The transfer's first origin, which a request keeps.
    pub(crate) fn first(&self) -> &'r Origin {
        self.first
    }
}

impl CredentialGate {
    /// The gate of a request that goes over no network (`file:`), which
    /// has no origin to keep the application's login from.
    pub(crate) fn local(_: GateKey) -> CredentialGate {
        CredentialGate {
            same: true,
            trusted: true,
        }
    }
}

/// Whether what the application said for the first origin may go to the
/// one a request is for, decided once as the request is made: the only
/// way to the tokens that let a custom Host, an Authorization, a Cookie
/// or the application's credentials into it.
#[derive(Debug)]
pub(crate) struct CredentialGate {
    same: bool,
    trusted: bool,
}

impl CredentialGate {
    pub(crate) fn same_origin(&self) -> Option<SameOrigin> {
        self.same.then_some(SameOrigin(()))
    }

    pub(crate) fn trusted(&self) -> Option<OriginTrusted> {
        self.trusted.then_some(OriginTrusted(()))
    }

    /// The gate of a request to `now` in a transfer that started at
    /// `first`, for a test's own request.
    #[cfg(test)]
    pub(crate) fn testing(first: &Peer, now: &Peer, unrestricted: bool) -> CredentialGate {
        let same = first == now;
        CredentialGate {
            same,
            trusted: same || unrestricted,
        }
    }
}

/// The request is for the origin the transfer started with
/// (`Curl_peer_equal`): its custom Host goes, and its TLS has the client's
/// identity.
#[derive(Clone, Copy, Debug)]
pub(crate) struct SameOrigin(());

impl SameOrigin {
    /// A test's own first origin.
    #[cfg(test)]
    pub(crate) fn testing() -> SameOrigin {
        SameOrigin(())
    }
}

/// The gate lets what the application said go to the request's origin
/// (`Curl_auth_allowed_to_host`): its login and token, its custom
/// Authorization and Cookie, Negotiate's ambient identity, a signature.
#[derive(Clone, Copy, Debug)]
pub(crate) struct OriginTrusted(());

impl OriginTrusted {
    /// A test's own leave.
    #[cfg(test)]
    pub(crate) fn testing() -> OriginTrusted {
        OriginTrusted(())
    }
}

/// A value the application gave for the transfer's first origin: its
/// login, its token, the service and the identity it authenticates as,
/// FTP's account. The application sets it; inside the library it is read
/// only with the leave of a gate that trusts the request's origin
/// ([`ForOrigin::get`]), so a reading that skips the gate does not
/// compile.
///
/// ```compile_fail,E0616
/// fn read(v: &curl_core::options::ForOrigin<Vec<u8>>) -> &Vec<u8> {
///     &v.0
/// }
/// ```
#[derive(Clone, PartialEq, Eq)]
pub struct ForOrigin<T>(T);

impl<T> ForOrigin<T> {
    pub const fn new(value: T) -> ForOrigin<T> {
        ForOrigin(value)
    }

    /// The value, for an origin the request's gate trusts.
    pub(crate) fn get(&self, _: OriginTrusted) -> &T {
        &self.0
    }
}

impl ForOrigin<Vec<u8>> {
    /// A copy, allocated fallibly.
    pub(crate) fn try_clone(&self) -> Result<ForOrigin<Vec<u8>>, curl_alloc::OutOfMemory> {
        use curl_alloc::TryVec as _;
        let mut copy = Vec::new();
        copy.try_extend_from_slice(&self.0)?;
        Ok(ForOrigin(copy))
    }
}

/// Said without the value, which is the first origin's alone.
impl<T> core::fmt::Debug for ForOrigin<T> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("ForOrigin(..)")
    }
}

/// Credentials the request's own URL or a `.netrc` entry for its host
/// carry go to its origin, which they were given for, wherever the
/// transfer started (`url_set_data_creds`). Not an `OriginTrusted`, and
/// never made one.
#[derive(Clone, Copy, Debug)]
pub(crate) struct OwnLeave(());

impl OwnLeave {
    /// Made only where credentials are taken from the URL or a `.netrc`
    /// entry (`auth::creds`).
    pub(in crate::auth) fn given() -> OwnLeave {
        OwnLeave(())
    }
}

/// What lets credentials go into a request to its origin: the gate's
/// leave, or their own; made of either, and opening nothing else.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Leave(());

impl Leave {
    pub(crate) fn of(_: OriginTrusted) -> Leave {
        Leave(())
    }

    pub(crate) fn own(_: OwnLeave) -> Leave {
        Leave(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::conn::Scheme;
    use curl_alloc::TryArc;

    fn peer(host: &[u8], port: u16) -> Peer {
        Peer::new(Scheme::HTTP, host.to_vec(), port, None)
    }

    /// The first request's peer is recorded as it is lent, and its gate
    /// compares it with itself; a later request to it is the same origin,
    /// and to any other is shut unless the application lets credentials
    /// follow; a later lend changes nothing, and a reset forgets it.
    #[test]
    fn the_gate_is_the_first_origin_s() {
        let key = || crate::proto::GateKey::testing();
        let here = peer(b"here.example", 80);
        let there = peer(b"there.example", 80);
        let mut first = FirstOrigin::fresh();
        let opened = first.lend(&here, false).unwrap().gate(&here, key());
        assert!(opened.same_origin().is_some() && opened.trusted().is_some());
        let other = first.lend(&there, false).unwrap().gate(&there, key());
        assert!(other.same_origin().is_none() && other.trusted().is_none());
        let same = first.lend(&there, false).unwrap().gate(&here, key());
        assert!(same.same_origin().is_some() && same.trusted().is_some());
        let followed = first.lend(&there, true).unwrap().gate(&there, key());
        assert!(followed.same_origin().is_none() && followed.trusted().is_some());
        first.reset();
        let anew = first.lend(&there, false).unwrap().gate(&there, key());
        assert!(anew.same_origin().is_some() && anew.trusted().is_some());
        let inherited = FirstOrigin::inherited(TryArc::try_new(here.try_clone().unwrap()).unwrap())
            .lend(&there, false)
            .unwrap()
            .gate(&there, key());
        assert!(inherited.same_origin().is_none() && inherited.trusted().is_none());
    }
}
