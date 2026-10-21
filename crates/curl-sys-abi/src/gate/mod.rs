//! The one gate every exported call into a handle passes (`lib/api.c`):
//! which calls may run while another call on the same handle is under
//! way, or inside one of its callbacks.

#![allow(
    dead_code,
    unused_imports,
    reason = "the handles that pass the gate come next"
)]

#[rustfmt::skip]
mod table;

pub(crate) use table::{EASY_MAX_DEPTH, EasyCall, MULTI_MAX_DEPTH, MultiCall};

/// What api.c allows an easy call (`Curl_eapi_fn_props`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct EasyRules {
    /// The call ends the handle.
    pub(crate) kills: bool,
    /// The call may run while another call on the handle, or on its
    /// multi, is under way.
    pub(crate) recurse: bool,
    /// The call is refused inside the multi's socket and timer callbacks.
    pub(crate) not_in_event: bool,
}

/// What api.c allows a multi call (`Curl_mapi_fn_props`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct MultiRules {
    /// The call ends the handle.
    pub(crate) kills: bool,
    /// The call may run while another call on the multi is under way.
    pub(crate) recurse: bool,
    /// The call may run inside a notify callback, whatever `recurse` says.
    pub(crate) in_notify: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A few rows, against lib/api.c as read by hand.
    #[test]
    fn reads_api_c() {
        let pause = EasyCall::Pause.rules();
        assert!(pause.recurse && pause.not_in_event && !pause.kills);
        assert!(EasyCall::Cleanup.rules().kills);
        assert!(!EasyCall::Perform.rules().recurse);
        assert!(EasyCall::Setopt.rules().recurse);
        let add = MultiCall::AddHandle.rules();
        assert!(!add.recurse && add.in_notify);
        assert!(MultiCall::Cleanup.rules().kills);
        assert!(!MultiCall::Perform.rules().in_notify);
        assert!(MultiCall::InfoRead.rules().recurse);
        assert_eq!((EASY_MAX_DEPTH, MULTI_MAX_DEPTH), (7, 15));
    }
}
