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

/// Where the transfer's first request went (`state.initial_origin`), once
/// it has gone: what the application said for it goes nowhere else. Only
/// a run that has made no request yet has none, which opens every gate.
#[derive(Debug)]
pub(crate) struct FirstOrigin(Option<Origin>);

impl FirstOrigin {
    /// A run's before its first request, or a pushed stream's request,
    /// which is a run of its own (C's pushed handle).
    pub(crate) fn fresh() -> FirstOrigin {
        FirstOrigin(None)
    }

    /// The first request's origin, recorded once: later ones change
    /// nothing.
    pub(crate) fn record(&mut self, origin: &Origin) {
        if self.0.is_none() {
            self.0 = Some(origin.clone());
        }
    }

    /// The transfer starts over.
    pub(crate) fn reset(&mut self) {
        self.0 = None;
    }

    /// What a request of this run decides its gate by; `unrestricted`
    /// lets credentials follow it anywhere (`CURLOPT_UNRESTRICTED_AUTH`).
    pub(crate) fn origins(&self, unrestricted: bool) -> Origins<'_> {
        Origins {
            first: self.0.as_deref(),
            unrestricted,
        }
    }

    /// Whether `peer` is the first origin.
    pub(crate) fn is(&self, peer: &Peer) -> bool {
        self.0.as_deref() == Some(peer)
    }
}

/// The first origin as a request is lent it (`Before`): it answers only
/// to the holder of the key, `RequestBase`, for the peer it stores.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Origins<'r> {
    first: Option<&'r Peer>,
    unrestricted: bool,
}

impl Origins<'_> {
    /// The gate of a request to `peer`: open for the transfer's first
    /// request; else whether `peer` is the first origin, and whether what
    /// the application said may go there (`Curl_auth_allowed_to_host`).
    pub(crate) fn gate(&self, peer: &Peer, _: GateKey) -> CredentialGate {
        match self.first {
            None => CredentialGate {
                same: true,
                trusted: true,
            },
            Some(first) => {
                let same = first == peer;
                CredentialGate {
                    same,
                    trusted: same || self.unrestricted,
                }
            }
        }
    }

    /// The gate of a request that goes over no network (`file:`), which
    /// has no origin to keep the application's login from.
    pub(crate) fn local(&self, _: GateKey) -> CredentialGate {
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

    /// A fresh run's gate is open; once the first origin is recorded, a
    /// request to it is the same origin, and to any other is shut unless
    /// the application lets credentials follow; a second record changes
    /// nothing, and a reset opens it again.
    #[test]
    fn the_gate_is_the_first_origin_s() {
        let key = || crate::proto::GateKey::testing();
        let here = peer(b"here.example", 80);
        let there = peer(b"there.example", 80);
        let mut first = FirstOrigin::fresh();
        let open = first.origins(false).gate(&there, key());
        assert!(open.same_origin().is_some() && open.trusted().is_some());
        first.record(&TryArc::try_new(peer(b"here.example", 80)).unwrap());
        first.record(&TryArc::try_new(peer(b"there.example", 80)).unwrap());
        assert!(first.is(&here) && !first.is(&there));
        let same = first.origins(false).gate(&here, key());
        assert!(same.same_origin().is_some() && same.trusted().is_some());
        let other = first.origins(false).gate(&there, key());
        assert!(other.same_origin().is_none() && other.trusted().is_none());
        let followed = first.origins(true).gate(&there, key());
        assert!(followed.same_origin().is_none() && followed.trusted().is_some());
        first.reset();
        let open = first.origins(false).gate(&there, key());
        assert!(open.same_origin().is_some() && open.trusted().is_some());
    }
}
