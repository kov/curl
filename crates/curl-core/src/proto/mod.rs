//! The protocols a transfer can speak, each a state the transfer holds
//! while it exchanges data.
//!
//! `file:` is built in. Tests have three more, networkless: `null:`, which
//! completes at once, `stall:`, which never does, and `script:`, which
//! delivers the pieces of its transfer's `Options::script`; and `tcp:`,
//! which connects to its URL's host and port and completes once
//! connected.

mod file;
#[cfg(any(test, feature = "test-util"))]
mod script;

use crate::conn::Scheme;
use crate::deliver::Pipeline;
use crate::error::ErrorKind;
use crate::multi::Host;
use crate::multi::state::StepCx;
use crate::options::Options;
use crate::url::Url;
#[cfg(any(test, feature = "test-util"))]
use crate::url::{GetOptions, Part};

/// A protocol's state for one transfer.
#[derive(Debug)]
pub(crate) enum ProtoState {
    File(file::Request),
    #[cfg(any(test, feature = "test-util"))]
    Null,
    #[cfg(any(test, feature = "test-util"))]
    Stall,
    #[cfg(any(test, feature = "test-util"))]
    Script(script::Player),
    #[cfg(any(test, feature = "test-util"))]
    Tcp,
}

/// What a protocol step achieved.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ProtoStep {
    /// The request is complete.
    Done,
    /// Nothing more until something happens.
    #[cfg_attr(
        not(any(test, feature = "test-util")),
        expect(dead_code, reason = "only the test protocols wait before HTTP")
    )]
    Blocked,
}

impl ProtoState {
    /// The protocol for `scheme`, lowercase, if this build has one, set up
    /// for `url`: what C's protocols do in their `setup_connection`, and
    /// `file:`'s connect, which opens the file before a connection is
    /// leased.
    pub(crate) fn start<H: Host>(
        scheme: &[u8],
        url: &Url,
        cx: &mut StepCx<'_, H>,
    ) -> Result<Option<ProtoState>, ErrorKind> {
        Ok(Some(match scheme {
            b"file" => ProtoState::File(file::Request::open(url, cx)?),
            #[cfg(any(test, feature = "test-util"))]
            b"null" => ProtoState::Null,
            #[cfg(any(test, feature = "test-util"))]
            b"stall" => ProtoState::Stall,
            #[cfg(any(test, feature = "test-util"))]
            b"script" => ProtoState::Script(script::Player::default()),
            #[cfg(any(test, feature = "test-util"))]
            b"tcp" => ProtoState::Tcp,
            _ => return Ok(None),
        }))
    }

    /// The host and port the request connects to, or none for a protocol
    /// that does its own I/O (C's `PROTOPT_NONETWORK`).
    #[cfg_attr(
        not(any(test, feature = "test-util")),
        expect(
            unused_variables,
            reason = "only the test protocol connects before HTTP"
        )
    )]
    pub(crate) fn network(&self, url: &Url) -> Result<Option<(Scheme, Vec<u8>, u16)>, ErrorKind> {
        match *self {
            ProtoState::File(_) => Ok(None),
            #[cfg(any(test, feature = "test-util"))]
            ProtoState::Null | ProtoState::Stall | ProtoState::Script(_) => Ok(None),
            #[cfg(any(test, feature = "test-util"))]
            ProtoState::Tcp => {
                let malformed = |_| ErrorKind::UrlMalformat;
                let host = url.get(Part::Host, GetOptions::NONE).map_err(malformed)?;
                let port = url.get(Part::Port, GetOptions::NONE).map_err(malformed)?;
                let port = std::str::from_utf8(&port)
                    .ok()
                    .and_then(|p| p.parse().ok())
                    .ok_or(ErrorKind::UrlMalformat)?;
                let scheme = Scheme {
                    name: "tcp",
                    reuse: true,
                };
                Ok(Some((scheme, host, port)))
            }
        }
    }

    /// Make the request (C's `do_it`): `file:`'s is the whole transfer;
    /// the test protocols have none to make.
    pub(crate) fn do_it<H: Host>(&mut self, cx: &mut StepCx<'_, H>) -> Result<(), ErrorKind> {
        match *self {
            ProtoState::File(ref mut f) => f.do_it(cx),
            #[cfg(any(test, feature = "test-util"))]
            ProtoState::Null | ProtoState::Stall | ProtoState::Script(_) | ProtoState::Tcp => {
                Ok(())
            }
        }
    }

    /// Whether the request, once made, exchanges anything more: C's
    /// transfer has a socket to receive or send on.
    pub(crate) fn exchanges(&self) -> bool {
        match *self {
            ProtoState::File(_) => false,
            #[cfg(any(test, feature = "test-util"))]
            ProtoState::Null | ProtoState::Stall | ProtoState::Script(_) | ProtoState::Tcp => true,
        }
    }

    /// Whether the request has a body to send (C's `CURL_REQ_WANT_SEND`
    /// at DID): `file:` writes its upload in DO.
    #[cfg_attr(
        not(any(test, feature = "test-util")),
        expect(unused_variables, reason = "only the test protocol sends at DID")
    )]
    pub(crate) fn wants_send(&self, options: &Options) -> bool {
        match *self {
            ProtoState::File(_) => false,
            #[cfg(any(test, feature = "test-util"))]
            ProtoState::Script(_) => script::wants_send(options),
            #[cfg(any(test, feature = "test-util"))]
            ProtoState::Null | ProtoState::Stall | ProtoState::Tcp => false,
        }
    }

    /// Whether the request holds output for the application.
    #[cfg(debug_assertions)]
    pub(crate) fn holds_output(&self) -> bool {
        match *self {
            // A write cannot pause it: it never holds.
            ProtoState::File(_) => false,
            #[cfg(any(test, feature = "test-util"))]
            ProtoState::Script(ref p) => p.holds_output(),
            #[cfg(any(test, feature = "test-util"))]
            ProtoState::Null | ProtoState::Stall | ProtoState::Tcp => false,
        }
    }

    /// The output of the request, for protocols that deliver any.
    pub(crate) fn pipeline_mut(&mut self) -> Option<&mut Pipeline> {
        match *self {
            ProtoState::File(ref mut f) => Some(f.pipeline_mut()),
            #[cfg(any(test, feature = "test-util"))]
            ProtoState::Script(ref mut p) => Some(p.pipeline_mut()),
            #[cfg(any(test, feature = "test-util"))]
            ProtoState::Null | ProtoState::Stall | ProtoState::Tcp => None,
        }
    }

    #[cfg_attr(
        not(any(test, feature = "test-util")),
        expect(unused_variables, reason = "only the test protocols exchange")
    )]
    pub(crate) fn step<H: Host>(&mut self, cx: &mut StepCx<'_, H>) -> Result<ProtoStep, ErrorKind> {
        match *self {
            ProtoState::File(_) => unreachable!("a file request exchanges nothing once made"),
            #[cfg(any(test, feature = "test-util"))]
            ProtoState::Null | ProtoState::Tcp => Ok(ProtoStep::Done),
            #[cfg(any(test, feature = "test-util"))]
            ProtoState::Stall => Ok(ProtoStep::Blocked),
            #[cfg(any(test, feature = "test-util"))]
            ProtoState::Script(ref mut p) => p.step(cx),
        }
    }
}
