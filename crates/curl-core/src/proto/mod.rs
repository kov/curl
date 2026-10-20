//! The protocols a transfer can speak, each a state the transfer holds
//! while it exchanges data.
//!
//! None is built in yet. Tests have two networkless ones: `null:`, which
//! completes at once, and `stall:`, which never does.

/// A protocol's state for one transfer.
#[derive(Debug)]
pub(crate) enum ProtoState {
    #[cfg(any(test, feature = "test-util"))]
    Null,
    #[cfg(any(test, feature = "test-util"))]
    Stall,
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
            _ => None,
        }
    }

    pub(crate) fn step(&mut self) -> ProtoStep {
        match *self {
            #[cfg(any(test, feature = "test-util"))]
            ProtoState::Null => ProtoStep::Done,
            #[cfg(any(test, feature = "test-util"))]
            ProtoState::Stall => ProtoStep::Blocked,
        }
    }
}
