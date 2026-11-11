//! What every network protocol's request holds: where it goes, the body
//! on its way to the application, and who it goes as.

use std::num::NonZeroU32;

use curl_alloc::TryVec as _;

use super::url_peer;
use crate::auth::creds::{CredentialGate, Credentials};
use crate::conn::{Peer, Scheme};
use crate::deliver::Pipeline;
use crate::error::{ErrorKind, url_error};
use crate::idn::Idn;
use crate::multi::Host;
use crate::multi::state::StepCx;
use crate::url::{GetOptions, Part, Url};

/// The fields a network protocol's `Request` has in common, which
/// `ProtoState` answers its questions of the request from.
#[derive(Debug)]
pub(crate) struct RequestBase {
    /// The scheme, the host as the URL names it, and the port the request
    /// goes to.
    pub(super) peer: Peer,
    /// The body on its way to the application.
    pub(super) pipeline: Pipeline,
    /// What the URL and the application say to log in with, until its
    /// route or the protocol's own login takes it; none for a protocol
    /// that reads none (DICT, Gopher, TFTP).
    pub(super) credentials: Option<Credentials>,
    /// Whether what the application said for the first origin may go to
    /// this one: its credentials, and the custom `Authorization:` and
    /// `Cookie:` a tunnel's `CONNECT` sends (`Curl_auth_allowed_to_host`),
    /// fixed as the request is made.
    pub(super) gate: CredentialGate,
}

impl RequestBase {
    /// The peer the request connects to, named again for `url`.
    pub(super) fn network(
        &self,
        url: &Url,
        scope: Option<NonZeroU32>,
        idn: Option<&dyn Idn>,
    ) -> Result<Peer, ErrorKind> {
        let mut host = Vec::new();
        host.try_extend_from_slice(self.peer.shown())
            .map_err(|_| ErrorKind::OutOfMemory)?;
        url_peer(
            (self.peer.scheme(), host, self.peer.port()),
            url,
            scope,
            idn,
        )
    }

    pub(super) fn scheme(&self) -> Scheme {
        self.peer.scheme()
    }
}

/// The gate of a request to `peer` in a transfer whose first request
/// went to `first`, none if this is it: shut where the origin is
/// another, unless the application lets credentials follow
/// (`Curl_auth_allowed_to_host`).
pub(super) fn gate_of<H: Host>(
    first: Option<&Peer>,
    peer: &Peer,
    cx: &mut StepCx<'_, H>,
) -> CredentialGate {
    match first {
        None => CredentialGate::FIRST,
        Some(first) => CredentialGate::new(first, peer, cx.easy().options().http.unrestricted_auth),
    }
}

/// The peer of `url`, a URL of `scheme`, at its port or the scheme's.
pub(super) fn peer_of<H: Host>(
    url: &Url,
    scheme: &[u8],
    cx: &mut StepCx<'_, H>,
) -> Result<Peer, ErrorKind> {
    let host = url.get(Part::Host, GetOptions::NONE).map_err(url_error)?;
    let port = url
        .get(
            Part::Port,
            GetOptions {
                default_port: true,
                ..GetOptions::NONE
            },
        )
        .map_err(url_error)?;
    let port = std::str::from_utf8(&port)
        .ok()
        .and_then(|p| p.parse().ok())
        .ok_or(ErrorKind::UrlMalformat)?;
    let scheme = Scheme::named(scheme).expect("libcurl knows the scheme");
    let scope = cx.easy().options().address_scope;
    let idn = cx.easy().libraries().idn;
    url_peer((scheme, host, port), url, scope, idn)
}
