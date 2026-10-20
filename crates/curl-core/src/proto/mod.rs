//! The protocols a transfer can speak, each a state the transfer holds
//! while it exchanges data.
//!
//! None is built in yet. Tests have three networkless ones: `null:`, which
//! completes at once, `stall:`, which never does, and `script:`, which
//! delivers the pieces of its transfer's `Options::script`.

#[cfg(any(test, feature = "test-util"))]
mod script;

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
