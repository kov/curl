//! The protocols a transfer can speak, each a state the transfer holds
//! while it exchanges data.
//!
//! None is built in yet. Tests have three networkless ones: `null:`, which
//! completes at once, `stall:`, which never does, and `script:`, which
//! delivers the pieces of its transfer's `Options::script`.

#[cfg(any(test, feature = "test-util"))]
mod script;

use crate::deliver::Pipeline;
use crate::error::ErrorKind;
use crate::multi::Host;
use crate::multi::state::StepCx;

/// A protocol's state for one transfer.
#[derive(Debug)]
pub(crate) enum ProtoState {
    #[cfg(any(test, feature = "test-util"))]
    Null,
    #[cfg(any(test, feature = "test-util"))]
    Stall,
    #[cfg(any(test, feature = "test-util"))]
    Script(script::Player),
}

/// What a protocol step achieved.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(
    not(any(test, feature = "test-util")),
    expect(dead_code, reason = "no protocol is built in before step 8")
)]
pub(crate) enum ProtoStep {
    /// The request is complete.
    Done,
    /// Nothing more until something happens.
    Blocked,
}

impl ProtoState {
    /// The protocol for `scheme`, lowercase, if this build has one.
    pub(crate) fn for_scheme(scheme: &[u8]) -> Option<ProtoState> {
        match scheme {
            #[cfg(any(test, feature = "test-util"))]
            b"null" => Some(ProtoState::Null),
            #[cfg(any(test, feature = "test-util"))]
            b"stall" => Some(ProtoState::Stall),
            #[cfg(any(test, feature = "test-util"))]
            b"script" => Some(ProtoState::Script(script::Player::default())),
            _ => None,
        }
    }

    /// Whether the request has a body to send (C's `CURL_REQ_WANT_SEND`
    /// at DID).
    #[cfg_attr(
        not(any(test, feature = "test-util")),
        expect(unused_variables, reason = "no protocol is built in before step 8")
    )]
    pub(crate) fn wants_send(&self, options: &crate::options::Options) -> bool {
        match *self {
            #[cfg(any(test, feature = "test-util"))]
            ProtoState::Script(_) => script::wants_send(options),
            #[cfg(any(test, feature = "test-util"))]
            ProtoState::Null | ProtoState::Stall => false,
        }
    }

    /// Whether the request holds output for the application.
    #[cfg(debug_assertions)]
    pub(crate) fn holds_output(&self) -> bool {
        match *self {
            #[cfg(any(test, feature = "test-util"))]
            ProtoState::Script(ref p) => p.holds_output(),
            #[cfg(any(test, feature = "test-util"))]
            ProtoState::Null | ProtoState::Stall => false,
        }
    }

    /// The output of the request, for protocols that deliver any.
    pub(crate) fn pipeline_mut(&mut self) -> Option<&mut Pipeline> {
        match *self {
            #[cfg(any(test, feature = "test-util"))]
            ProtoState::Script(ref mut p) => Some(p.pipeline_mut()),
            #[cfg(any(test, feature = "test-util"))]
            ProtoState::Null | ProtoState::Stall => None,
        }
    }

    #[cfg_attr(
        not(any(test, feature = "test-util")),
        expect(unused_variables, reason = "no protocol is built in before step 8")
    )]
    pub(crate) fn step<H: Host>(&mut self, cx: &mut StepCx<'_, H>) -> Result<ProtoStep, ErrorKind> {
        match *self {
            #[cfg(any(test, feature = "test-util"))]
            ProtoState::Null => Ok(ProtoStep::Done),
            #[cfg(any(test, feature = "test-util"))]
            ProtoState::Stall => Ok(ProtoStep::Blocked),
            #[cfg(any(test, feature = "test-util"))]
            ProtoState::Script(ref mut p) => p.step(cx),
        }
    }
}
